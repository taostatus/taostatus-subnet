from __future__ import annotations

"""secqurityVali/job.py - the isolated evaluation run, end to end.

One job = one agent evaluated against one fresh challenge. It ties together
everything built so far:

    challenge  ->  target container  }  on a private, internal network
                   agent container   }  agent under monitored gVisor
                        |
                   findings.json  +  strace behaviour log
                        |
                   TASK score (canary)  +  SAFETY verdict (behaviour)
                        |
                   teardown: agent, target, network, output dir

Two halves, kept apart so the logic is testable without a daemon:

  * assemble_result() is pure -- given the raw findings text, the behaviour log
    text, and the challenge, it produces the JobResult. Unit-tested.
  * run_job() does the docker orchestration -- create the network, start the
    target, run the agent, collect, tear down. Verified on the isolation host.

The network is `--internal`: the agent can reach the target but has no route to
the internet or the host. The agent is given the target's IP directly and its
DNS is pointed at nothing, so it needs no name resolution and cannot use DNS to
exfiltrate. Teardown runs on every path, so no job leaves state behind.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from secqurityVali import constants as C
from secqurityVali.behavior import BehaviorReport, Violation, analyze, safety_verdict
from secqurityVali.eval.challenge import Challenge, generate_challenge
from secqurityVali.eval.findings import Findings, FindingsError, parse_findings_bytes
from secqurityVali.eval.task_score import TaskResult, score_task
from secqurityVali.targets.sqli_v1.provision import TARGET_IMAGE, TARGET_PORT, docker_env_args


@dataclass
class JobResult:
    """The full outcome of one evaluation run: what the agent found (task) and
    what it did (safety), plus the raw evidence and the run's mechanics."""

    run_id: str
    accepted: bool
    task: TaskResult | None
    safe: bool
    violations: list[Violation] = field(default_factory=list)
    agent_exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    parse_error: str | None = None
    error: str | None = None            # our fault (docker/orchestration), not the miner's

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "accepted": self.accepted,
            "task": self.task.to_dict() if self.task else None,
            "safe": self.safe,
            "violations": [v.to_dict() for v in self.violations],
            "agent_exit_code": self.agent_exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "parse_error": self.parse_error,
            "error": self.error,
        }


# --- the pure half: evidence -> result ---------------------------------

def assemble_result(
    run_id: str,
    challenge: Challenge,
    findings_raw: bytes,
    behaviour_text: str,
    *,
    agent_exit_code: int | None,
    timed_out: bool,
    duration_ms: int = 0,
    replay_confirmed: bool = False,
) -> JobResult:
    """Turn the raw evidence a run produced into a scored JobResult. Pure: no
    docker, no clock. This is where task and safety are combined, and it is the
    one place the rule lives -- a blocking safety violation rejects the run
    regardless of the task score."""
    # Safety first: it can veto everything.
    report: BehaviorReport = analyze(behaviour_text or "")
    safe, blocking = safety_verdict(report)

    # Task: parse the agent's findings (untrusted) and score against the key.
    task: TaskResult | None = None
    parse_error: str | None = None
    try:
        findings: Findings = parse_findings_bytes(findings_raw, expected_run_id=run_id)
        task = score_task(challenge, findings, replay_confirmed=replay_confirmed)
    except FindingsError as exc:
        parse_error = str(exc)

    # Accepted only if the agent proved the exploit (canary) AND behaved.
    accepted = bool(safe and task and task.canary_found)

    return JobResult(
        run_id=run_id,
        accepted=accepted,
        task=task,
        safe=safe,
        violations=blocking + [v for v in report.violations if v not in blocking],
        agent_exit_code=agent_exit_code,
        timed_out=timed_out,
        duration_ms=duration_ms,
        parse_error=parse_error,
    )


# --- the docker half: run_job ------------------------------------------

def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, shell=False
    )


def _network_create(name: str) -> None:
    _run(["network", "create", "--internal", name], timeout=C.DOCKER_CLI_TIMEOUT_S)


def _network_remove(name: str) -> None:
    _run(["network", "rm", name], timeout=C.DOCKER_CLI_TIMEOUT_S)


def _rm_container(name: str) -> None:
    _run(["rm", "--force", "--volumes", name], timeout=C.DOCKER_CLI_TIMEOUT_S)


def _container_ip(name: str, network: str) -> str:
    fmt = "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}"
    res = _run(["inspect", "-f", fmt, name], timeout=C.DOCKER_CLI_TIMEOUT_S)
    return (res.stdout or "").strip()


def _agent_create_args(name, network, agent_image, target_ip, out_dir, run_id, timeout_s):
    """The full agent invocation. Like the dry-run's flags, but on the job
    network with the target reachable, /out mounted, and the challenge context
    in the environment. Built as a list so a test can assert on it."""
    return [
        "create", "--name", name,
        "--runtime", C.JOB_AGENT_RUNTIME,
        "--network", network,
        # target reachable by IP; DNS pointed at nothing so no name resolution
        # and no DNS-based exfiltration.
        "--dns", "127.0.0.1",
        "--memory", C.DRY_RUN_MEMORY,
        "--memory-swap", C.DRY_RUN_MEMORY_SWAP,
        "--cpus", str(C.DRY_RUN_CPUS),
        "--pids-limit", str(C.DRY_RUN_PIDS_LIMIT),
        "--read-only",
        "--tmpfs", C.DRY_RUN_TMPFS,
        # the one writable, size-capped place the agent may leave output
        "--mount", f"type=bind,src={out_dir},dst={C.JOB_OUTPUT_MOUNT}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--label", C.DRY_RUN_LABEL,
        "-e", f"TARGET_URL=http://{target_ip}:{TARGET_PORT}",
        "-e", f"OUTPUT_PATH={C.JOB_OUTPUT_MOUNT}/{C.JOB_FINDINGS_NAME}",
        "-e", f"RUN_ID={run_id}",
        "-e", f"TIME_BUDGET_S={timeout_s}",
        agent_image,
    ]


def run_job(
    agent_image: str,
    *,
    challenge: Challenge | None = None,
    timeout_s: int = C.JOB_AGENT_TIMEOUT_S,
    keep: bool = False,
) -> JobResult:
    """Run one full evaluation and return its scored result.

    Never raises: an orchestration failure becomes a JobResult with `error`
    set (our fault, retryable), never an exception the caller must handle.
    Everything created is destroyed before returning.
    """
    challenge = challenge or generate_challenge()
    run_id = uuid.uuid4().hex
    short = run_id[:12]
    network = C.JOB_NETWORK_PREFIX + short
    target_name = C.JOB_TARGET_NAME_PREFIX + short
    agent_name = C.JOB_AGENT_NAME_PREFIX + short
    out_dir = tempfile.mkdtemp(prefix="secval-out-")
    # The agent runs as a non-root uid inside the container; make the mounted
    # output dir world-writable so it can write findings.json regardless of
    # which uid the image uses.
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass
    started = time.monotonic()
    agent_cid = ""

    try:
        _network_create(network)

        # target on the internal network, seeded with this run's challenge
        tgt = _run(
            ["run", "-d", "--name", target_name, "--network", network,
             "--runtime", C.JOB_TARGET_RUNTIME, *docker_env_args(challenge), TARGET_IMAGE],
            timeout=C.DOCKER_CLI_TIMEOUT_S,
        )
        if tgt.returncode != 0:
            return _our_fault(run_id, f"target start failed: {tgt.stderr.strip()[:300]}")

        target_ip = _container_ip(target_name, network)
        if not target_ip:
            return _our_fault(run_id, "could not determine target IP on the job network")

        # give the target a moment to bind its port
        time.sleep(2)

        # agent, under the monitored runtime
        created = _run(
            _agent_create_args(agent_name, network, agent_image, target_ip, out_dir,
                               run_id, timeout_s),
            timeout=C.DOCKER_CLI_TIMEOUT_S,
        )
        if created.returncode != 0:
            return _our_fault(run_id, f"agent create failed: {created.stderr.strip()[:300]}")
        agent_cid = (created.stdout or "").strip()

        _run(["start", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)

        timed_out = False
        try:
            _run(["wait", agent_name], timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _run(["kill", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)

        exit_code = _exit_code(agent_name)
        duration_ms = int((time.monotonic() - started) * 1000)

        findings_raw = _read_findings(out_dir)
        behaviour_text = _read_behaviour(agent_cid)

        # If the agent reported a reproduction, confirm the exploit reproduces
        # against a FRESH target (new canary, same structure). This is what
        # separates a working exploit from a lucky or memorised canary, and it
        # is what upgrades the task score from "canary only" to full.
        replay_confirmed = _maybe_replay(challenge, findings_raw)

        return assemble_result(
            run_id, challenge, findings_raw, behaviour_text,
            agent_exit_code=exit_code, timed_out=timed_out, duration_ms=duration_ms,
            replay_confirmed=replay_confirmed,
        )
    except subprocess.TimeoutExpired as exc:
        return _our_fault(run_id, f"docker call timed out: {exc}")
    except Exception as exc:  # noqa: BLE001 - orchestration must not crash the caller
        return _our_fault(run_id, f"{type(exc).__name__}: {exc}")
    finally:
        if not keep:
            _rm_container(agent_name)
            _rm_container(target_name)
            _network_remove(network)
            shutil.rmtree(out_dir, ignore_errors=True)


def _maybe_replay(challenge: Challenge, findings_raw: bytes) -> bool:
    """Parse the agent's findings for a reproduction and, if present, confirm it
    reproduces on a fresh target. Best-effort: any failure means "not
    confirmed", never an exception."""
    from secqurityVali.eval.findings import parse_findings_bytes
    from secqurityVali.replay import run_replay
    try:
        findings = parse_findings_bytes(findings_raw)
    except Exception:
        return False
    if not findings.reproduction:
        return False
    return run_replay(challenge, findings.reproduction)


def _our_fault(run_id: str, message: str) -> JobResult:
    return JobResult(run_id=run_id, accepted=False, task=None, safe=True, error=message)


def _exit_code(name: str) -> int | None:
    res = _run(["inspect", "-f", "{{.State.ExitCode}}", name], timeout=C.DOCKER_CLI_TIMEOUT_S)
    try:
        return int((res.stdout or "").strip())
    except ValueError:
        return None


def _read_findings(out_dir: str) -> bytes:
    path = Path(out_dir) / C.JOB_FINDINGS_NAME
    try:
        return path.read_bytes()[: 1 * 1024 * 1024 + 1]
    except OSError:
        return b""


def _read_behaviour(agent_cid: str) -> str:
    if not agent_cid:
        return ""
    import glob
    text = ""
    for d in glob.glob(os.path.join(C.JOB_MON_LOG_ROOT, agent_cid + "*")):
        for path in glob.glob(os.path.join(d, "*boot.txt")):
            try:
                with open(path, "r", errors="replace") as fh:
                    text += fh.read()
            except OSError:
                pass
    return text
