from __future__ import annotations

"""secqurityVali/audit_loop.py - turn one customer audit job into a result.

The validator pulls a job {run_id, agent_id, target_url} from the backend and
calls process_audit_job, which enforces the operational-audit security policy
before anything runs:

  * the agent MUST be vetted (passed the sandbox admission gate) -- a customer
    can never trigger an operational run of an un-vetted or unknown agent;
  * the agent's image must be obtainable (the miner is serving it);
  * the target is validated inside run_audit (anti-SSRF), which never raises.

Any failure yields a `failed` result (so the customer sees it and no emission is
earned), never an exception. The seams (`is_vetted`, `resolve_agent`,
`run_audit`) are injected, so this policy is unit-tested without docker.
"""

from secqurityVali import constants as C
from secqurityVali.audit_runner import AuditReport
from secqurityVali.audit_runner import run_audit as _run_audit
from secqurityVali.audit_runner import run_audit_from_repo as _run_audit_from_repo
from secqurityVali.audit_runner import run_browser_audit as _run_browser_audit


def process_audit_job(
    job: dict,
    *,
    is_vetted,
    resolve_agent,
    run_audit=_run_audit,
    run_audit_from_repo=_run_audit_from_repo,
    run_browser_audit=_run_browser_audit,
    timeout_s: int | None = None,
) -> dict:
    """Run one audit job and return the result body (RunResultIn shape).

    The job's scope picks the path:
      * engine == "browser" (Live URL) -> run_browser_audit (our trusted
        Playwright+Chromium agent: renders a JS/SPA app, logs in, captures the
        real API surface and attacks it -- the only path that sees a modern SPA)
      * "repo" -> run_audit_from_repo (white-box: code analysis on the source,
        then a targeted attack on the built+run app, in an isolated sandbox)
      * anything else -> run_audit (black-box against a live URL)

    `is_vetted(agent_id) -> bool`    : agent passed the admission gate
    `resolve_agent(agent_id) -> str` : a runnable image ref, or None/raise if not
    """
    run_id = job.get("run_id")
    agent_id = job.get("agent_id")
    target = job.get("target_url")   # a live URL, or a git repo URL for source_type=repo
    scope = job.get("scope")         # passed through untouched to the black-box runner
    source_type = (scope.get("source_type") if isinstance(scope, dict) else None) or "url"
    engine = (scope.get("engine") if isinstance(scope, dict) else None)   # "browser" -> headless SPA path
    aspects = scope.get("aspects") if isinstance(scope, dict) else None   # what to check
    credentials = job.get("credentials")   # transient test creds (authenticated attack); never logged
    if not (run_id and agent_id and target):
        return AuditReport.failed("malformed job (missing run_id/agent_id/target)").to_result()

    kwargs = {}
    if timeout_s is not None:
        kwargs["timeout_s"] = timeout_s

    # Browser engine (Live-URL, modern/SPA): our own trusted Playwright agent, not
    # a miner image -- so it does not go through miner vetting/resolution.
    #
    # SECURITY GATE: this path currently runs the headless browser with full network
    # egress, so a customer-controlled page's JavaScript (or a DNS-rebind/redirect)
    # could reach cloud metadata / internal services from the isolation host -- an
    # SSRF. The path is DISABLED by default (BROWSER_AUDIT_ENABLED) and must stay off
    # on any host reachable by untrusted customers until that egress is forced
    # through a public-only filtering proxy. Refuse here (the authoritative boundary),
    # not just in the UI.
    if engine == "browser" and source_type != "repo":
        if not C.BROWSER_AUDIT_ENABLED:
            return AuditReport.failed(
                "browser (modern-app) audits are temporarily unavailable"
            ).to_result()
        report = run_browser_audit(target, credentials=credentials, **kwargs)
        return report.to_result()

    # Security gate: only vetted agents may ever run against a real target.
    if not is_vetted(agent_id):
        return AuditReport.failed("agent is not vetted for operational runs").to_result()

    try:
        image = resolve_agent(agent_id)
    except Exception as exc:  # noqa: BLE001 - resolution failure is the miner's/our side, not scored
        return AuditReport.failed(f"agent could not be obtained: {type(exc).__name__}").to_result()
    if not image:
        return AuditReport.failed("agent unavailable (miner not serving it)").to_result()

    if source_type == "repo":
        report = run_audit_from_repo(image, target, aspects=aspects,
                                     credentials=credentials, **kwargs)  # white-box
    else:
        report = run_audit(image, target, scope=scope,
                           credentials=credentials, **kwargs)  # black-box URL
    return report.to_result()
