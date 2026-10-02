from __future__ import annotations

"""masxai/audit_client.py - validator <-> marketplace backend, operational audits.

The marketplace backend queues customer audit runs. The security validator pulls
one with GET /api/internal/next-job, runs the agent against the target (Step 1),
and returns the validated result with POST /api/internal/runs/{id}/result.

Same backend and bearer token as the catalog push (masxai/constants.py:
MASXAI_MARKETPLACE_URL + MASXAI_MARKETPLACE_TOKEN). Stdlib-only (urllib), and
best-effort by contract: any failure returns None/False and never raises, so a
backend problem can never disturb the validator's chain duties.
"""

import json
import os
import urllib.parse
import urllib.request

from masxai import constants as C

NEXT_JOB_PATH = "/api/internal/next-job"
RESULT_PATH = "/api/internal/runs/{run_id}/result"


def _default_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float):
    """Perform the request; return (status_code, body_bytes). urllib-based."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status), resp.read()


class AuditBackendClient:
    """Pull audit jobs and return their results. Never raises."""

    def __init__(self, base_url: str, token: str, *, timeout: float = C.MARKETPLACE_TIMEOUT,
                 transport=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._transport = transport or _default_transport

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def claim_next_job(self, validator_hotkey: str = "") -> dict | None:
        """Claim the oldest pending audit, or None when the queue is empty or the
        backend is unreachable (both are 'nothing to do')."""
        url = f"{self.base_url}{NEXT_JOB_PATH}?validator={urllib.parse.quote(validator_hotkey)}"
        try:
            status, data = self._transport("GET", url, self._auth(), None, self.timeout)
            if 200 <= int(status) < 300:
                obj = json.loads(data or b"{}")
                job = obj.get("job") if isinstance(obj, dict) else None
                return job if isinstance(job, dict) else None
        except Exception:  # noqa: BLE001 - a backend problem must never break the validator
            pass
        return None

    def post_result(self, run_id: str, result: dict) -> bool:
        """Return the validated result for a run. True on a 2xx, else False."""
        url = f"{self.base_url}{RESULT_PATH.format(run_id=urllib.parse.quote(str(run_id)))}"
        headers = {**self._auth(), "Content-Type": "application/json"}
        try:
            body = json.dumps(result).encode("utf-8")
            status, _ = self._transport("POST", url, headers, body, self.timeout)
            return 200 <= int(status) < 300
        except Exception:  # noqa: BLE001
            return False


def open_audit_client_from_env() -> AuditBackendClient | None:
    """Build from config, or None when unconfigured (the feature's kill switch;
    the validator then runs no operational audits)."""
    url = (os.getenv(C.MARKETPLACE_URL_ENV) or "").strip()
    token = (os.getenv(C.MARKETPLACE_TOKEN_ENV) or "").strip()
    if not url or not token:
        return None
    try:
        timeout = float(os.getenv(C.MARKETPLACE_TIMEOUT_ENV, C.MARKETPLACE_TIMEOUT))
    except (TypeError, ValueError):
        timeout = C.MARKETPLACE_TIMEOUT
    return AuditBackendClient(url, token, timeout=timeout)
