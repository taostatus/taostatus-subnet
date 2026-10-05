from __future__ import annotations

"""secqurityVali/audit_runner.py - run ONE vetted agent against ONE real target.

This composes the proven pieces into a single real-target audit:

    validate_target (anti-SSRF)  ->  pin IP
    start egress-proxy container  (pinned target, measuring, hardened)
    start agent on a --internal network, DNS blackholed, pointed at the proxy
    collect findings + proxy stats + gVisor behaviour
    certify safety (fail closed if monitoring is missing)
    confirm the finding by replay (1d, injected)
    score  ->  measured report (the backend's RunResultIn shape)

Every container/network/temp file is torn down in `finally`, so a failure never
leaks an egress-capable proxy. The scoring (`score_audit`) is pure and
gate-first: an unsafe, uncertifiable, or unconfirmed run earns nothing.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field

from secqurityVali import constants as C
from secqurityVali import job
from secqurityVali import repo_target
from secqurityVali import replay_confirm
from secqurityVali.behavior import analyze, safety_verdict
from secqurityVali.target_guard import TargetRejected, validate_target

PROXY_IMAGE = os.getenv("AUDIT_PROXY_IMAGE", "python:3.12-alpine")
PROXY_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "egress_proxy.py")
PROXY_PORT = 8080

# What a "good" audit looks like, for normalising the speed/efficiency axes.
TARGET_TIME_MS = 30_000
TARGET_REQUESTS = 200


# --- the report (maps to marketplace-server's RunResultIn) --------------

@dataclass
class AuditReport:
    status: str = "completed"             # completed | failed
    confirmed: bool | None = None
    clean: bool | None = None
    safe: bool | None = None
    score: float | None = None
    duration_ms: int | None = None
    request_count: int | None = None
    error_count: int | None = None
    false_positives: int | None = None
    findings: list = field(default_factory=list)
    error: str | None = None

    def to_result(self) -> dict:
        """The POST /api/internal/runs/{id}/result body."""
        return {
            "status": self.status,
            "confirmed": self.confirmed,
            "clean": self.clean,
            "safe": self.safe,
            "score": self.score,
            "duration_ms": self.duration_ms,
            "request_count": self.request_count,
            "error_count": self.error_count,
            "false_positives": self.false_positives,
            "findings": self.findings,
            "error": self.error,
        }

    @classmethod
    def failed(cls, reason: str) -> "AuditReport":
        return cls(status="failed", error=reason, score=0.0, confirmed=False, safe=False)


# --- the scoring: pure, gate-first -------------------------------------

def score_audit(
    *,
    confirmed: bool,
    safe: bool,
    monitoring_available: bool,
    timed_out: bool,
    duration_ms: int,
    request_count: int,
    error_count: int,
    false_positives: int,
    target_time_ms: int = TARGET_TIME_MS,
    target_requests: int = TARGET_REQUESTS,
) -> tuple[float, bool]:
    """Return (score, clean). Correctness-anchored with speed/efficiency/
    cleanliness refinements. Hard gates first, so none of the refinements can
    rescue a run that should earn nothing:

      * monitoring missing  -> cannot certify safety -> 0 (fail closed)
      * not safe            -> 0
      * not confirmed       -> 0 (no real vuln proven)
    """
    clean = (not timed_out) and (int(error_count) == 0)

    if not monitoring_available or not safe:
        return 0.0, clean
    if not confirmed:
        return 0.0, clean

    speed = min(1.0, target_time_ms / max(int(duration_ms), 1))
    efficiency = min(1.0, target_requests / max(int(request_count), 1))
    cleanliness = 1.0 if clean else 0.0

    score = 1.0 * (0.50 + 0.20 * speed + 0.15 * efficiency + 0.15 * cleanliness)
    score -= 0.10 * max(0, int(false_positives))
    return max(0.0, min(1.0, score)), clean


# --- the orchestration (integration-tested on the isolation host) -------

def _read_proxy_stats(stats_dir: str) -> dict:
    try:
        with open(os.path.join(stats_dir, "stats.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _parse_findings(findings_raw: bytes) -> list:
    """Best-effort: the agent's findings as a list for the customer report.
    Never raises; unparseable findings yield an empty list."""
    try:
        data = json.loads(findings_raw or b"{}")
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        found = data.get("findings")
        return found if isinstance(found, list) else []
    return data if isinstance(data, list) else []


def run_audit(
    agent_image: str,
    target_url: str,
    *,
    scope: dict | None = None,
    timeout_s: int = C.JOB_AGENT_TIMEOUT_S,
    allow_private: bool = False,
    confirm=None,
) -> AuditReport:
    """Run one audit and return a measured report. Never raises: any failure is a
    `failed` report, and everything created is destroyed before returning.

    `confirm(pinned, findings) -> (confirmed, false_positives)` defaults to the
    boolean-differential replay; a test can inject its own.
    """
    confirm = confirm or replay_confirm.confirm

    # 1. anti-SSRF gate -- before ANY container starts.
    try:
        pinned = validate_target(target_url, allow_private=allow_private)
    except TargetRejected as exc:
        return AuditReport.failed(f"target rejected: {exc}")

    run_id = uuid.uuid4().hex
    short = run_id[:12]
    int_net = C.JOB_NETWORK_PREFIX + "ai-" + short     # --internal: agent + proxy
    eg_net = C.JOB_NETWORK_PREFIX + "ae-" + short      # egress: proxy only
    proxy_name = "secaudit-proxy-" + short
    agent_name = C.JOB_AGENT_NAME_PREFIX + "a" + short

    out_dir = tempfile.mkdtemp(prefix="secaudit-out-")
    stats_dir = tempfile.mkdtemp(prefix="secaudit-stats-")
    try:
        os.chmod(out_dir, 0o777)
        os.chmod(stats_dir, 0o777)
    except OSError:
        pass
    resolv_path = job._blackhole_resolv()
    started = time.monotonic()
    agent_cid = ""

    try:
        job._network_create(int_net)                    # --internal
        job._run(["network", "create", eg_net], timeout=C.DOCKER_CLI_TIMEOUT_S)

        # proxy: hardened, on the internal net, then given the egress leg.
        proxy_env = {
            "PROXY_TARGET_IP": pinned.ip, "PROXY_TARGET_PORT": str(pinned.port),
            "PROXY_TARGET_SCHEME": pinned.scheme, "PROXY_TARGET_HOST": pinned.host,
            "PROXY_LISTEN_PORT": str(PROXY_PORT), "PROXY_STATS_PATH": "/stats/stats.json",
        }
        if allow_private:
            proxy_env["PROXY_ALLOW_PRIVATE_TARGET"] = "1"
        proxy_args = [
            "run", "-d", "--name", proxy_name, "--network", int_net,
            "--memory", C.DRY_RUN_MEMORY, "--cpus", str(C.DRY_RUN_CPUS),
            "--pids-limit", str(C.DRY_RUN_PIDS_LIMIT),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{PROXY_SCRIPT}:/app/egress_proxy.py:ro",
            "-v", f"{stats_dir}:/stats",
        ]
        for k, v in proxy_env.items():
            proxy_args += ["-e", f"{k}={v}"]
        proxy_args += [PROXY_IMAGE, "python", "/app/egress_proxy.py"]
        pr = job._run(proxy_args, timeout=C.DOCKER_CLI_TIMEOUT_S)
        if pr.returncode != 0:
            return AuditReport.failed(f"proxy start failed: {pr.stderr.strip()[:300]}")
        job._run(["network", "connect", eg_net, proxy_name], timeout=C.DOCKER_CLI_TIMEOUT_S)

        proxy_ip = job._container_ip(proxy_name, int_net)
        if not proxy_ip:
            return AuditReport.failed("could not determine proxy IP")
        time.sleep(2)   # let the proxy bind

        # agent: same hardening as the vetting sandbox, but pointed at the proxy.
        agent_args = _agent_args(agent_name, int_net, agent_image, proxy_ip,
                                 out_dir, resolv_path, run_id, timeout_s)
        created = job._run(agent_args, timeout=C.DOCKER_CLI_TIMEOUT_S)
        if created.returncode != 0:
            return AuditReport.failed(f"agent create failed: {created.stderr.strip()[:300]}")
        agent_cid = (created.stdout or "").strip()
        job._run(["start", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)

        timed_out = False
        try:
            job._run(["wait", agent_name], timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            job._run(["kill", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)
        duration_ms = int((time.monotonic() - started) * 1000)

        # collect
        findings_raw = job._read_findings(out_dir)
        behaviour = job._read_behaviour(agent_cid)
        monitoring_available = bool(behaviour.strip())
        stats = _read_proxy_stats(stats_dir)
        request_count = int(stats.get("request_count", 0) or 0)
        error_count = int(stats.get("error_count", 0) or 0)

        # safety: fail closed if monitoring is missing.
        if monitoring_available:
            safe, _ = safety_verdict(analyze(behaviour))
        else:
            safe = False

        # confirm (replay) + score
        findings = _parse_findings(findings_raw)
        confirmed, false_positives = confirm(pinned, findings)
        score, clean = score_audit(
            confirmed=confirmed, safe=safe, monitoring_available=monitoring_available,
            timed_out=timed_out, duration_ms=duration_ms, request_count=request_count,
            error_count=error_count, false_positives=false_positives,
        )
        return AuditReport(
            status="completed", confirmed=confirmed, clean=clean, safe=safe, score=score,
            duration_ms=duration_ms, request_count=request_count, error_count=error_count,
            false_positives=false_positives, findings=findings,
        )
    except subprocess.TimeoutExpired as exc:
        return AuditReport.failed(f"docker call timed out: {exc}")
    except Exception as exc:  # noqa: BLE001 - orchestration must not crash the caller
        return AuditReport.failed(f"{type(exc).__name__}: {exc}")
    finally:
        job._rm_container(agent_name)
        job._rm_container(proxy_name)
        job._network_remove(int_net)
        job._network_remove(eg_net)
        shutil.rmtree(out_dir, ignore_errors=True)
        shutil.rmtree(stats_dir, ignore_errors=True)
        try:
            os.unlink(resolv_path)
        except OSError:
            pass


def _agent_args(name, network, agent_image, proxy_ip, out_dir, resolv_path, run_id, timeout_s):
    """Agent invocation: mirrors the vetting sandbox hardening (job.py) -- gVisor
    runtime, --internal network, blackhole DNS, read-only root, dropped caps,
    size-capped /out -- but TARGET_URL points at the proxy, not a synthetic
    container."""
    return [
        "create", "--name", name,
        "--runtime", C.JOB_AGENT_RUNTIME,
        "--network", network,
        "--dns", "127.0.0.1",
        "--mount", f"type=bind,src={resolv_path},dst=/etc/resolv.conf,readonly",
        "--memory", C.DRY_RUN_MEMORY,
        "--memory-swap", C.DRY_RUN_MEMORY_SWAP,
        "--cpus", str(C.DRY_RUN_CPUS),
        "--pids-limit", str(C.DRY_RUN_PIDS_LIMIT),
        "--read-only",
        "--tmpfs", C.DRY_RUN_TMPFS,
        "--mount", f"type=bind,src={out_dir},dst={C.JOB_OUTPUT_MOUNT}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--label", C.DRY_RUN_LABEL,
        "-e", f"TARGET_URL=http://{proxy_ip}:{PROXY_PORT}",
        "-e", f"OUTPUT_PATH={C.JOB_OUTPUT_MOUNT}/{C.JOB_FINDINGS_NAME}",
        "-e", f"RUN_ID={run_id}",
        "-e", f"TIME_BUDGET_S={timeout_s}",
        agent_image,
    ]


# --- repo target: audit a customer git repo (built + run in isolation) --

def _confirm_in_net(target: repo_target.RepoTarget, findings: list) -> tuple[bool, int]:
    """Replay findings against a repo-built target from a trusted container ON its
    internal network -- the validator host has no route to it. Reuses the exact
    `replay_confirm` logic (repo_confirmer.py). Fails closed: any error, any
    unparseable verdict, is (not-confirmed, 0)."""
    data_dir = tempfile.mkdtemp(prefix="secaudit-cfm-")
    name = C.REPO_CONFIRMER_NAME_PREFIX + uuid.uuid4().hex[:12]
    try:
        try:
            os.chmod(data_dir, 0o777)
        except OSError:
            pass
        with open(os.path.join(data_dir, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings or [], fh)
        args = [
            "run", "--rm", "--name", name,
            "--network", target.network, "--label", C.REPO_LABEL,
            "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{repo_target.REPLAY_SCRIPT}:/app/replay_confirm.py:ro",
            "-v", f"{repo_target.CONFIRMER_SCRIPT}:/app/repo_confirmer.py:ro",
            "-v", f"{data_dir}:/data:ro",
            "-e", f"TARGET_IP={target.ip}",
            "-e", f"TARGET_PORT={target.port}",
            "-e", f"TARGET_SCHEME={target.scheme}",
            "-e", f"TARGET_HOST={target.ip}",
            "-e", "FINDINGS_PATH=/data/findings.json",
            C.REPO_UTIL_IMAGE, "python", "/app/repo_confirmer.py",
        ]
        res = job._run(args, timeout=C.REPO_HEALTH_TIMEOUT_S + C.DOCKER_CLI_TIMEOUT_S)
        if res.returncode != 0:
            return False, 0
        out = (res.stdout or "").strip()
        line = out.splitlines()[-1] if out else "{}"
        verdict = json.loads(line)
        return bool(verdict.get("confirmed")), int(verdict.get("false_positives") or 0)
    except subprocess.TimeoutExpired:
        job._rm_container(name)
        return False, 0
    except Exception:  # noqa: BLE001 - confirmation failure is fail-closed, never fatal
        return False, 0
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)


def run_audit_from_repo(
    agent_image: str,
    repo_url: str, *,
    ref: str | None = None,
    subdir: str | None = None,
    port: int | None = None,
    env: dict | None = None,
    git_token: str | None = None,
    build_network: bool = True,
    timeout_s: int = C.JOB_AGENT_TIMEOUT_S,
    provision=None,
    confirm=None,
) -> AuditReport:
    """Audit a customer's git repo: build + run it in isolation, then run the
    agent against it on the same zero-egress network. Never raises -- any failure
    is a `failed` report, and every container/image/network/temp file is torn
    down before returning.

    `provision`/`confirm` are injectable for tests; they default to the real
    `repo_target.provision_repo_target` and the in-network replay confirmer.
    """
    provision = provision or repo_target.provision_repo_target
    confirm = confirm or _confirm_in_net

    # 1. build + run the repo as an isolated target (fails closed, self-cleans).
    try:
        target = provision(
            repo_url, ref=ref, subdir=subdir, port=port, env=env,
            git_token=git_token, build_network=build_network,
        )
    except repo_target.RepoError as exc:
        return AuditReport.failed(f"repo target: {exc}")
    except Exception as exc:  # noqa: BLE001
        return AuditReport.failed(f"repo target: {type(exc).__name__}: {exc}")

    run_id = uuid.uuid4().hex
    agent_name = C.JOB_AGENT_NAME_PREFIX + "ra" + run_id[:10]
    out_dir = tempfile.mkdtemp(prefix="secaudit-out-")
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass
    resolv_path = job._blackhole_resolv()
    started = time.monotonic()
    agent_cid = ""
    try:
        # 2. agent on the SAME internal network, pointed straight at the target IP
        #    (no proxy: there is no egress to proxy -- everything stays in-network).
        create_args = job._agent_create_args(
            agent_name, target.network, agent_image, target.ip, out_dir, run_id,
            timeout_s, resolv_path, target.port,
        )
        created = job._run(create_args, timeout=C.DOCKER_CLI_TIMEOUT_S)
        if created.returncode != 0:
            return AuditReport.failed(f"agent create failed: {created.stderr.strip()[:300]}")
        agent_cid = (created.stdout or "").strip()
        job._run(["start", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)

        timed_out = False
        try:
            job._run(["wait", agent_name], timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            job._run(["kill", agent_name], timeout=C.DOCKER_CLI_TIMEOUT_S)
        duration_ms = int((time.monotonic() - started) * 1000)

        # 3. collect: findings + gVisor behaviour (safety is fail-closed)
        findings_raw = job._read_findings(out_dir)
        behaviour = job._read_behaviour(agent_cid)
        monitoring_available = bool(behaviour.strip())
        safe = safety_verdict(analyze(behaviour))[0] if monitoring_available else False

        # 4. confirm by in-network replay, then score (no proxy -> request_count
        #    is not measured; the gate-first score still requires confirmed+safe).
        findings = _parse_findings(findings_raw)
        confirmed, false_positives = confirm(target, findings)
        score, clean = score_audit(
            confirmed=confirmed, safe=safe, monitoring_available=monitoring_available,
            timed_out=timed_out, duration_ms=duration_ms, request_count=0,
            error_count=0, false_positives=false_positives,
        )
        return AuditReport(
            status="completed", confirmed=confirmed, clean=clean, safe=safe, score=score,
            duration_ms=duration_ms, request_count=None, error_count=0,
            false_positives=false_positives, findings=findings,
        )
    except subprocess.TimeoutExpired as exc:
        return AuditReport.failed(f"docker call timed out: {exc}")
    except Exception as exc:  # noqa: BLE001
        return AuditReport.failed(f"{type(exc).__name__}: {exc}")
    finally:
        job._rm_container(agent_name)
        target.teardown()
        shutil.rmtree(out_dir, ignore_errors=True)
        try:
            os.unlink(resolv_path)
        except OSError:
            pass
