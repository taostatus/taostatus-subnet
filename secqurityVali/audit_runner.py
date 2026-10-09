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

from secqurityVali import code_analysis
from secqurityVali import constants as C
from secqurityVali import static_scan
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
    # True when the report is code-analysis only (repo cloned + statically scanned,
    # never built/attacked) -- findings are POTENTIAL, not replay-confirmed. The
    # backend passes findings through as JSON, so this also rides along per-finding
    # as status="potential"; the top-level flag is for callers that want one bit.
    analysis_only: bool = False

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
    credentials=None,
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
                                 out_dir, resolv_path, run_id, timeout_s,
                                 credentials=credentials)
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


def _agent_args(name, network, agent_image, proxy_ip, out_dir, resolv_path, run_id,
                timeout_s, credentials=None):
    """Agent invocation: mirrors the vetting sandbox hardening (job.py) -- gVisor
    runtime, --internal network, blackhole DNS, read-only root, dropped caps,
    size-capped /out -- but TARGET_URL points at the proxy, not a synthetic
    container. `credentials` (optional) are handed over as the SECAUDIT_CREDS secret
    so the agent authenticates and attacks behind login; safe because the agent is
    zero-egress (it can only reach the one pinned target through the proxy) and its
    container is destroyed after the run."""
    args = [
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
    ]
    if credentials:
        args += ["-e", f"SECAUDIT_CREDS={json.dumps(credentials)}"]
    args.append(agent_image)
    return args


# --- Live-URL modern-app audit: headless browser agent --------------------

def run_browser_audit(
    target_url: str,
    *,
    timeout_s: int = C.BROWSER_AGENT_TIMEOUT_S,
    allow_private: bool = False,
    credentials=None,
) -> AuditReport:
    """Audit a Live modern/SPA URL with the headless-browser agent.

    The reference agent crawls raw HTML, so a JS-rendered SPA (Firebase, Next.js)
    looks empty to it. This path instead runs the Playwright+Chromium agent
    (`BROWSER_AGENT_IMAGE`): it renders the page, logs in with `credentials`,
    explores, captures the *real* API surface (including a cross-host backend) and
    attacks it, writing potentials to findings.json.

    Unlike `run_audit`, the browser needs real network egress (a single-host proxy
    cannot carry a SPA's cross-host API calls), so this is for our trusted
    reference browser agent only, not an untrusted miner image. The target is still
    anti-SSRF gated before anything starts, the container is gVisor-isolated with
    caps dropped, and it is destroyed after the run. Findings are oracle-based
    POTENTIALS (not canary replay-confirmed), so the report is `analysis_only`.
    """
    try:
        validate_target(target_url, allow_private=allow_private)
    except TargetRejected as exc:
        return AuditReport.failed(f"target rejected: {exc}")

    run_id = uuid.uuid4().hex
    name = C.JOB_AGENT_NAME_PREFIX + "b" + run_id[:12]
    out_dir = tempfile.mkdtemp(prefix="secbrowser-out-")
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass
    started = time.monotonic()

    env = {
        "TARGET_URL": target_url,
        "OUTPUT_PATH": f"{C.JOB_OUTPUT_MOUNT}/{C.JOB_FINDINGS_NAME}",
        "RUN_ID": run_id,
        "TIME_BUDGET_S": str(timeout_s),
    }
    if credentials:
        env["SECAUDIT_CREDS"] = json.dumps(credentials)

    args = [
        "run", "--rm", "--name", name,
        "--runtime", C.JOB_TARGET_RUNTIME,            # gVisor (runsc), no behaviour monitor
        "--memory", C.BROWSER_AGENT_MEMORY,
        "--cpus", C.BROWSER_AGENT_CPUS,
        "--shm-size", C.BROWSER_AGENT_SHM,            # Chromium needs a real /dev/shm
        "--pids-limit", "512",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--tmpfs", "/tmp:rw,size=256m",
        "--mount", f"type=bind,src={out_dir},dst={C.JOB_OUTPUT_MOUNT}",
    ]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    args.append(C.BROWSER_AGENT_IMAGE)

    try:
        proc = job._run(args, timeout=timeout_s + C.DOCKER_CLI_TIMEOUT_S)
        duration_ms = int((time.monotonic() - started) * 1000)
        if proc.returncode != 0:
            return AuditReport.failed(
                f"browser agent exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}"
            )

        doc = _read_browser_doc(out_dir)
        findings = doc.get("findings") if isinstance(doc.get("findings"), list) else []
        tested = doc.get("tested_endpoints") if isinstance(doc.get("tested_endpoints"), list) else []
        findings = _normalise_browser_findings(findings)
        if doc.get("login_attempted"):
            findings = findings + [_login_status_note(bool(doc.get("authenticated")))]
        if tested:
            findings = findings + [_tested_endpoints_note(tested)]

        confirmed = any((f.get("status") == "confirmed") for f in findings)
        real = [f for f in findings if f.get("type") != "recon"]
        return AuditReport(
            status="completed",
            confirmed=confirmed,
            clean=True,
            safe=True,
            score=0.0,                                 # Live-URL audit: a service, not benchmark-scored
            duration_ms=duration_ms,
            request_count=len(tested) or None,
            error_count=0,
            false_positives=0,
            findings=findings,
            analysis_only=not confirmed,
        )
    except subprocess.TimeoutExpired:
        job._rm_container(name)
        return AuditReport.failed("browser audit timed out")
    except Exception as exc:  # noqa: BLE001 - orchestration must not crash the caller
        return AuditReport.failed(f"{type(exc).__name__}: {exc}")
    finally:
        job._rm_container(name)
        shutil.rmtree(out_dir, ignore_errors=True)


def _read_browser_doc(out_dir: str) -> dict:
    """The browser agent's findings.json as a dict (never raises)."""
    try:
        raw = job._read_findings(out_dir)
        data = json.loads(raw or b"{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError, OSError):
        return {}


def _normalise_browser_findings(findings: list) -> list:
    """Keep only well-formed finding dicts and stamp the browser scanner tag so the
    customer report renders them like any other potential."""
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        f.setdefault("status", "potential")
        f.setdefault("scanner", "browser")
        out.append(f)
    return out


def _login_status_note(authenticated: bool) -> dict:
    """One informational row telling the user whether the agent actually logged in
    with the test credentials -- so a '0 findings' result can't be mistaken for a
    clean app when login silently failed."""
    if authenticated:
        detail = ("Logged in with the test credentials -- the authenticated area and "
                  "its API were explored and tested.")
        sev = "info"
    else:
        detail = ("Test credentials were supplied but the agent could not confirm a "
                  "successful login (the form may use different fields, or login "
                  "failed) -- results below reflect the PUBLIC surface only. Check the "
                  "login URL and field names, or use a token.")
        sev = "low"
    return {
        "type": "recon", "severity": sev, "status": "info", "scanner": "browser",
        "endpoint": "authentication", "parameter": "", "detail": detail,
    }


def _tested_endpoints_note(tested: list) -> dict:
    """One informational row so the report shows which endpoints the browser
    actually hit -- the 'what was tested' trail the user asked to see."""
    eps = [str(e) for e in tested if isinstance(e, (str, int))][:60]
    return {
        "type": "recon",
        "severity": "info",
        "status": "info",
        "scanner": "browser",
        "endpoint": f"{len(eps)} endpoint(s)",
        "parameter": "",
        "detail": "Browser agent rendered the app and tested these endpoints: "
                  + ", ".join(eps),
    }


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


# --- white-box: code analysis -> attack hints -> source-located report --

_MAX_HINTS = 60


def _hints_env(candidates) -> dict:
    """Turn code-analysis candidates into a SECAUDIT_HINTS env the agent reads,
    so it attacks the REAL endpoints/params the source exposes. Only candidates
    tied to an endpoint are useful to the attacker; sinks with no route are kept
    for the report, not the attack."""
    items = []
    for c in candidates:
        if c.endpoint:
            items.append({"endpoint": c.endpoint, "parameter": c.parameter, "category": c.category})
        if len(items) >= _MAX_HINTS:
            break
    return {"SECAUDIT_HINTS": json.dumps(items)} if items else {}


def _attach_source_locations(findings, candidates) -> None:
    """Attach the file:line of the matching code-analysis candidate to each
    finding, so a CONFIRMED vuln points straight at the vulnerable source."""
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        ep = (f.get("endpoint") or "").rstrip("/")
        pm = f.get("parameter") or f.get("param") or ""
        for c in candidates:
            if c.endpoint and c.endpoint.rstrip("/") == ep and (not pm or not c.parameter or c.parameter == pm):
                f["source_file"] = c.file
                f["source_line"] = c.line
                f["sink"] = c.sink
                break


def _merge_findings(agent_findings, static_findings, confirmed: bool) -> list:
    """Combine the DYNAMIC and STATIC passes into one customer report, so neither
    is wasted:

      * confirmed exploits (replay-proven) come first as status "confirmed";
      * every Layer-1 static finding (Semgrep/Trivy) rides along as "potential",
        except one that sits at the exact file:line of a confirmed exploit
        (that weakness is already shown, proven).

    An UNconfirmed attack contributes no findings of its own (we never present an
    unverified agent claim as real) -- only the static potentials remain."""
    out: list = []
    seen_loc: set = set()
    if confirmed:
        for f in agent_findings or []:
            if not isinstance(f, dict):
                continue
            f = dict(f)
            f["status"] = "confirmed"
            out.append(f)
            loc = (f.get("source_file"), f.get("source_line"))
            if loc != (None, None):
                seen_loc.add(loc)
    for s in static_findings or []:
        if not isinstance(s, dict):
            continue
        loc = (s.get("source_file"), s.get("source_line"))
        if loc != (None, None) and loc in seen_loc:
            continue                      # already shown as a confirmed exploit
        out.append(s)
    return out


def run_static_audit_from_repo(
    repo_url: str, *,
    ref: str | None = None,
    subdir: str | None = None,
    git_token: str | None = None,
    reason: str | None = None,
    aspects=None,
    provision_source=None,
    scan=None,
) -> AuditReport:
    """Layer-1-only audit: clone the repo's source and statically scan it (Semgrep
    + Trivy, any language) for weaknesses. No build, no run, no attack -- so
    findings are POTENTIAL (unconfirmed) and the report earns nothing (score 0,
    confirmed False). This is the path for any public repo we can't or won't run
    (no Dockerfile, etc.). Never raises; a clone failure is a `failed` report.
    Self-cleans the clone.

    `provision_source`/`scan` are injectable for tests (default: the real
    clone-only provisioner and static_scan.run_static_scan)."""
    provision_source = provision_source or repo_target.provision_source_only
    scan = scan or static_scan.run_static_scan
    try:
        target = provision_source(repo_url, ref=ref, subdir=subdir, git_token=git_token)
    except repo_target.RepoError as exc:
        return AuditReport.failed(f"repo source: {exc}")
    except Exception as exc:  # noqa: BLE001
        return AuditReport.failed(f"repo source: {type(exc).__name__}: {exc}")
    try:
        scan_root = os.path.join(target.clone_dir, "src")
        if subdir:
            scan_root = os.path.join(scan_root, subdir)
        findings = scan(scan_root, aspects=aspects)   # status "potential", ranked
        return AuditReport(
            status="completed", confirmed=False, clean=None, safe=None,
            score=0.0, findings=findings, analysis_only=True,
        )
    except Exception as exc:  # noqa: BLE001
        return AuditReport.failed(f"static analysis failed: {type(exc).__name__}: {exc}")
    finally:
        target.teardown()


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
    aspects=None,
    credentials=None,
    provision=None,
    confirm=None,
    static_fallback=None,
    scan=None,
) -> AuditReport:
    """Audit a customer's git repo: build + run it in isolation, then run the
    agent against it on the same zero-egress network. Never raises -- any failure
    is a `failed` report, and every container/image/network/temp file is torn
    down before returning.

    If the repo can't be built/run (no Dockerfile, compose-only, won't start),
    we DON'T give up -- we fall back to a static code-analysis report so any
    public repo still returns something useful (just unconfirmed).

    `provision`/`confirm`/`static_fallback`/`scan` are injectable for tests; they
    default to the real `repo_target.provision_repo_target`, the in-network replay
    confirmer, `run_static_audit_from_repo`, and `static_scan.run_static_scan`.
    """
    provision = provision or repo_target.provision_repo_target
    confirm = confirm or _confirm_in_net
    static_fallback = static_fallback or run_static_audit_from_repo
    scan = scan or static_scan.run_static_scan

    # The customer's chosen aspects. If they didn't ask for a LIVE EXPLOIT, skip
    # the whole build+attack (slow, needs Docker) and just run the static scan.
    asp = set(aspects) if aspects is not None else None
    if asp is not None and "exploit" not in asp:
        return static_fallback(repo_url, ref=ref, subdir=subdir, git_token=git_token,
                               aspects=asp, reason="live exploit not requested")

    # 1. build + run the repo as an isolated target (fails closed, self-cleans).
    try:
        target = provision(
            repo_url, ref=ref, subdir=subdir, port=port, env=env,
            git_token=git_token, build_network=build_network,
        )
    except repo_target.RepoError as exc:
        # Can't run it -> still give the customer the Layer-1 static report. The
        # fallback re-clones (cheap, no build) and self-reports a clone failure.
        return static_fallback(repo_url, ref=ref, subdir=subdir, git_token=git_token,
                               aspects=asp, reason=str(exc))
    except Exception as exc:  # noqa: BLE001
        return AuditReport.failed(f"repo target: {type(exc).__name__}: {exc}")

    # WHITE-BOX: read the source first. Code analysis finds the real endpoints,
    # params and dangerous sinks (file:line); the agent then attacks THOSE,
    # instead of guessing a candidate list. Best-effort -- a failure just falls
    # back to black-box (no hints).
    # The repo is cloned into clone_dir/"src" (see repo_target), so that dir IS the
    # user's repo root -- analyze it for clean, repo-relative paths in the report.
    candidates = []
    try:
        candidates = code_analysis.analyze_source(os.path.join(target.clone_dir, "src"))
    except Exception:  # noqa: BLE001
        candidates = []
    hints = _hints_env(candidates)

    # Authenticated attack: hand the agent the test credentials as a secret env var
    # (JSON). Safe -- the agent is zero-egress, so even a malicious agent cannot
    # exfiltrate them, and its container is destroyed after the run. Never logged.
    agent_env = dict(hints)
    if credentials:
        agent_env["SECAUDIT_CREDS"] = json.dumps(credentials)

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
        # White-box: mount the cloned source READ-ONLY so the agent can analyse the
        # code it attacks (not just the host-side hints). Safe: zero-egress agent,
        # and for the benchmark the canary is runtime-only (this is the customer
        # path anyway). clone_dir/"src" is the repo root the agent sees at /src.
        create_args = job._agent_create_args(
            agent_name, target.network, agent_image, target.ip, out_dir, run_id,
            timeout_s, resolv_path, target.port, extra_env=agent_env,
            source_dir=os.path.join(target.clone_dir, "src"),
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
        agent_findings = _parse_findings(findings_raw)
        _attach_source_locations(agent_findings, candidates)   # file:line on exploited vulns
        confirmed, false_positives = confirm(target, agent_findings)
        score, clean = score_audit(
            confirmed=confirmed, safe=safe, monitoring_available=monitoring_available,
            timed_out=timed_out, duration_ms=duration_ms, request_count=0,
            error_count=0, false_positives=false_positives,
        )
        # Layer 1: run the full static scan (Semgrep + Trivy, any language) on the
        # same source, best-effort. Merge it with the dynamic result so the report
        # shows confirmed exploits AND every static weakness -- a buildable-but-
        # unexploited repo still returns real breadth.
        try:
            static_findings = scan(os.path.join(target.clone_dir, "src"), aspects=asp)
        except Exception:  # noqa: BLE001 - static scan must never fail the audit
            static_findings = []
        findings = _merge_findings(agent_findings, static_findings, confirmed)
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
