"""secqurityVali/sandbox_entry.py - the entrypoint of the Python-script sandbox.

In the Python-script admission model a miner submits ONE file, `agent.py`, that
defines `agent_main(ctx) -> list[Finding]` - not a whole Docker image. The
validator runs a single fixed, audited base image whose only moving part is that
one file, mounted read-only at /sandbox/agent.py. There is no attacker-controlled
image to load or vet, no layers to scan, no reserved-tag tricks: the exact same
sandbox (gVisor, zero-egress proxy, read-only root, dropped caps, size-capped
/out) wraps every miner identically, and only a few hundred bytes of Python
differ between runs.

This module is that base image's entrypoint. It:

  1. reads the run contract from the environment - the SAME env the Docker-image
     agents received: TARGET_URL, OUTPUT_PATH, RUN_ID, TIME_BUDGET_S and the
     optional SECAUDIT_CREDS secret (so the agent can attack behind login);
  2. loads the miner's `agent_main` from the mounted /sandbox/agent.py;
  3. runs it through `run_agent`, which enforces the scope / rate / wall-clock
     caps, injects the customer credentials, and - because the agent is untrusted
     - never lets it crash the runner or escape its budget;
  4. writes the findings to OUTPUT_PATH as JSON, in the shape the validator's
     replay-confirm (secqurityVali/replay_confirm.py) consumes.

It ALWAYS writes a findings file - an empty list on any failure - so a crashing,
hanging, or hostile agent never leaves the validator waiting; it simply scores
zero. Nothing the agent does is trusted: the proof that a finding is real is the
validator's independent replay of the agent's own payload against a fresh canary,
never this process's self-report.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import traceback
from urllib.parse import parse_qsl, urlsplit

# /app is on PYTHONPATH (set in the base image); import the audited SDK from there.
from secqurityVali.agent_sdk.context import Credentials, Finding, Scope
from secqurityVali.agent_sdk.runner import RunConfig, run_agent

# How the SDK's string confidence maps onto the numeric [0,1] the admission
# grader's schema requires (secqurityVali/eval/findings.py validates it strictly).
_CONFIDENCE = {"proven": 0.99, "confirmed": 0.99, "potential": 0.5, "possible": 0.4}

# The miner's agent is mounted here, read-only, by the validator. It is NEVER on
# sys.path (so a module it drops cannot shadow a stdlib or SDK import); it is
# loaded from this explicit path alone.
AGENT_PATH = os.getenv("AGENT_PATH", "/sandbox/agent.py")


def _defines_agent_main(path: str) -> bool:
    """Decide the run mode WITHOUT executing the miner code: does the module
    define a top-level `agent_main` (SDK style), or is it a self-contained script
    (an `if __name__ == '__main__'` guard) that runs itself? Parses only."""
    try:
        tree = ast.parse(open(path, "r", encoding="utf-8").read())
    except Exception:  # noqa: BLE001 - unreadable/unparsable -> let the SDK path error clearly
        return True
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "agent_main":
            return True
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "agent_main" for t in node.targets):
            return True
    return False


def _load_agent_main(path: str):
    """Load `agent_main` from the mounted agent file. Executing the miner's
    top-level code here is safe: this whole process already runs inside the
    gVisor + zero-egress sandbox, so an import side effect can reach nothing."""
    if not os.path.isfile(path):
        raise RuntimeError(f"no agent file mounted at {path}")
    spec = importlib.util.spec_from_file_location("miner_agent", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load agent module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, "agent_main", None)
    if not callable(fn):
        raise RuntimeError("agent.py does not define a callable agent_main(ctx)")
    return fn


def _run_self_contained(agent_path: str, out_path: str, run_id: str, budget: int) -> int:
    """Run a self-contained agent (no agent_main): a standalone script that reads
    TARGET_URL / OUTPUT_PATH / RUN_ID / SECAUDIT_CREDS from the environment and
    writes its own findings.json. It runs as an isolated (-I), time-bounded
    subprocess inside this same sandbox, so it is contained exactly like an SDK
    agent. The script owns OUTPUT_PATH; we only backfill an empty findings file if
    it produced none, so the validator never waits on a missing file."""
    err = None
    try:
        r = subprocess.run([sys.executable, "-I", agent_path], env=os.environ.copy(),
                           timeout=budget, check=False, capture_output=True)
        if r.returncode != 0:
            err = f"exit={r.returncode}"
        tail = (r.stderr or b"").decode("utf-8", "replace")[-2000:]
        if tail:
            sys.stderr.write(tail)
    except subprocess.TimeoutExpired:
        err = "timeout"
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
    if not os.path.isfile(out_path):
        _write_findings(out_path, _build_findings_doc(
            run_id, [], {"error": err or "no output", "mode": "self-contained"}))
    print(f"sandbox_entry: self-contained agent done (err={err})",
          file=sys.stderr, flush=True)
    return 0


def _credentials_from_env() -> "Credentials | None":
    """Rebuild the customer's authenticated session from the SECAUDIT_CREDS secret
    the validator passes (json: {cookies, bearer, headers}). Absent or malformed
    -> an unauthenticated run (the agent still works, just as a guest)."""
    raw = os.getenv("SECAUDIT_CREDS")
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except Exception:  # noqa: BLE001 - a malformed secret must not abort the run
        return None
    if not isinstance(d, dict):
        return None
    return Credentials(
        cookies=d.get("cookies") or {},
        bearer=d.get("bearer"),
        headers=d.get("headers") or {},
    )


def _scope_from_env() -> Scope:
    """Optional scope narrowing (SECAUDIT_SCOPE json: {include, exclude}). The
    default - empty include - puts the whole pinned target in scope, which is what
    a synthetic admission target wants."""
    raw = os.getenv("SECAUDIT_SCOPE")
    if not raw:
        return Scope()
    try:
        d = json.loads(raw)
        return Scope(
            include=tuple(d.get("include") or ()),
            exclude=tuple(d.get("exclude") or ()),
            destructive=bool(d.get("destructive", False)),
        )
    except Exception:  # noqa: BLE001
        return Scope()


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _confidence_float(value) -> float:
    """The SDK uses a string confidence ("proven"); the grader's schema needs a
    number in [0,1]. Map the known words; already-numeric values pass through."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value)))
    return _CONFIDENCE.get(str(value).strip().lower(), 0.5)


def _finding_to_entry(f: Finding) -> dict:
    """One SDK `Finding` -> one findings[] entry in the schema BOTH consumers
    accept: the admission grader (secqurityVali/eval/findings.py: needs numeric
    `confidence`, reads `canary`) and the customer-audit replay
    (secqurityVali/replay_confirm.py: reads `method`/`location`/`value`). Extra
    keys are ignored by each, so one entry serves both."""
    return {
        "endpoint": f.endpoint,
        "parameter": f.parameter,
        "injection_type": f.category or "sql_injection",
        "category": f.category,
        "severity": f.severity,
        "confidence": _confidence_float(f.confidence),
        "title": f.title,
        "detail": f.detail,
        "canary": f.canary,
        "payload": f.payload,
        "value": f.value,
        "method": f.method or "GET",
        "location": f.location or "query",
        "response_excerpt": (f.evidence or "")[:4096],
        "evidence": f.evidence,
    }


def _reproduction_for(findings: list[Finding]) -> list[dict]:
    """Auto-build the structured replay recipe the admission gate re-runs against
    a FRESH canary (secqurityVali/replay.py). For each injection finding that
    carries a payload + parameter, emit one step placing the exact payload in the
    named parameter -- so a genuine exploit re-extracts the new canary, while a
    memorised/guessed one cannot. Only GET/POST steps (the schema's allow-list)."""
    steps: list[dict] = []
    for i, f in enumerate(findings):
        if not (f.payload and f.parameter):
            continue
        method = (f.method or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        sp = urlsplit(f.endpoint or "")
        query = dict(parse_qsl(sp.query))
        query[f.parameter] = f.payload
        steps.append({
            "finding_index": i,
            "method": method,
            "path": sp.path or f.endpoint or "/",
            "query": query,
        })
    return steps


def _build_findings_doc(run_id: str, findings: list[Finding], meta: dict) -> dict:
    """The full findings.json: the grader validates `run_id` against this run,
    reads `findings[].canary` and the `reproduction` recipe. `agent` is
    display-only metadata, never scored."""
    return {
        "run_id": run_id,
        "schema_version": "1.0",
        "agent": {"name": "miner-agent", "version": ""},
        "findings": [_finding_to_entry(f) for f in findings],
        "reproduction": _reproduction_for(findings),
        "meta": meta,
    }


def _write_findings(path: str, payload: dict) -> None:
    """Atomically write the findings file the validator reads. Written even on
    failure so the orchestrator never blocks on a missing file."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 - last-ditch direct write
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
        except Exception:
            pass


def main() -> int:
    out_path = os.getenv("OUTPUT_PATH", "/out/findings.json")
    run_id = os.getenv("RUN_ID", "")
    findings: list[Finding] = []
    meta: dict = {"error": None}
    try:
        target = os.environ["TARGET_URL"]  # required; absence is a harness bug
        try:
            budget = int(os.getenv("TIME_BUDGET_S", "300"))
        except ValueError:
            budget = 300

        # Self-contained agent (no agent_main): a standalone script that writes its
        # own findings.json. Run it directly and return; nothing below applies.
        if not _defines_agent_main(AGENT_PATH):
            return _run_self_contained(AGENT_PATH, out_path, run_id, budget)

        cfg = RunConfig(
            target_url=target,
            scope=_scope_from_env(),
            credentials=_credentials_from_env(),
            # LLM is reached through an inference proxy the validator provides (empty
            # by default -> a purely deterministic agent needs no model and still runs)
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
            timeout_s=budget,
            use_browser=_env_flag("USE_BROWSER"),
            login_email=os.getenv("LOGIN_EMAIL") or None,
            login_password=os.getenv("LOGIN_PASSWORD") or None,
            login_path=os.getenv("LOGIN_PATH", "/auth/login"),
        )

        agent_main = _load_agent_main(AGENT_PATH)
        result = run_agent(agent_main, cfg)
        findings = result.findings
        meta = {
            "runner_run_id": result.run_id,
            "error": result.error,
            "http_requests": result.http_requests,
            "llm_calls": result.llm_calls,
            "llm_tokens": result.llm_tokens,
            "duration_ms": result.duration_ms,
            "num_findings": len(findings),
        }
    except Exception as exc:  # noqa: BLE001 - never leave without a findings file
        meta = {"error": f"{type(exc).__name__}: {exc}"}
        traceback.print_exc(file=sys.stderr)

    doc = _build_findings_doc(run_id, findings, meta)
    _write_findings(out_path, doc)
    print(f"sandbox_entry: wrote {len(findings)} finding(s) to {out_path} "
          f"(error={meta.get('error')})", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
