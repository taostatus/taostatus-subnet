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

from secqurityVali.audit_runner import AuditReport
from secqurityVali.audit_runner import run_audit as _run_audit


def process_audit_job(
    job: dict,
    *,
    is_vetted,
    resolve_agent,
    run_audit=_run_audit,
    timeout_s: int | None = None,
) -> dict:
    """Run one audit job and return the result body (RunResultIn shape).

    `is_vetted(agent_id) -> bool`    : agent passed the admission gate
    `resolve_agent(agent_id) -> str` : a runnable image ref, or None/raise if not
    `run_audit(image, url, ...)`     : the Step-1 runner (never raises)
    """
    run_id = job.get("run_id")
    agent_id = job.get("agent_id")
    target_url = job.get("target_url")
    if not (run_id and agent_id and target_url):
        return AuditReport.failed("malformed job (missing run_id/agent_id/target_url)").to_result()

    # Security gate: only vetted agents may ever run against a real target.
    if not is_vetted(agent_id):
        return AuditReport.failed("agent is not vetted for operational runs").to_result()

    try:
        image = resolve_agent(agent_id)
    except Exception as exc:  # noqa: BLE001 - resolution failure is the miner's/our side, not scored
        return AuditReport.failed(f"agent could not be obtained: {type(exc).__name__}").to_result()
    if not image:
        return AuditReport.failed("agent unavailable (miner not serving it)").to_result()

    kwargs = {"scope": job.get("scope")}
    if timeout_s is not None:
        kwargs["timeout_s"] = timeout_s
    report = run_audit(image, target_url, **kwargs)   # never raises; failures are `failed` reports
    return report.to_result()
