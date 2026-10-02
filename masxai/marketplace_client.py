from __future__ import annotations

"""masxai/marketplace_client.py - validator -> marketplace backend handoff.

After the security validator scores an agent, it pushes that agent's METADATA and
SCORES (never the image or code) to the marketplace backend, which the frontend
reads. This is the catalog model: the validator stays the evaluator; the backend
is storage + API.

Stdlib-only (urllib), so it adds no dependency to the neuron and is unit-testable
with an injected transport. Best-effort by contract: any failure returns False
and never raises, so a backend outage can never disturb a validator round.

Config (see masxai/constants.py): MASXAI_MARKETPLACE_URL + MASXAI_MARKETPLACE_TOKEN.
Both unset => open_marketplace_client_from_env() returns None and nothing is sent.
"""

import json
import os
import urllib.request

from masxai import constants as C

INGEST_PATH = "/api/internal/agents"


def build_agent_payload(
    *,
    miner_hotkey: str,
    uid: int | None,
    overall_score: float,
    categories: dict[str, float],
    status: str = "active",
    netuid: int | None = None,
    mechid: int | None = None,
    run: dict | None = None,
) -> dict:
    """Shape one agent's catalog record for POST /api/internal/agents.

    The marketplace id is the miner hotkey for now (one agent per miner); it can
    become the image layer digest later without changing the backend contract.
    `run` (this round's evaluation: variant/task_score/safe/requests) is included
    only when the agent was evaluated this round, so the backend can show recent
    runs and derive stats.
    """
    payload = {
        "agent_digest": miner_hotkey,
        "miner_hotkey": miner_hotkey,
        "uid": uid,
        "netuid": netuid,
        "mechid": mechid,
        "overall_score": float(overall_score),
        "status": status,
        "categories": {k: float(v) for k, v in (categories or {}).items()},
    }
    if run is not None:
        payload["run"] = run
    return payload


def _default_post(url: str, headers: dict, body: bytes, timeout: float) -> int:
    """POST and return the HTTP status code (urllib)."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status)


class MarketplaceClient:
    """Thin POST client for the marketplace internal API. `transport` is the
    function that actually sends the request (overridable in tests)."""

    def __init__(self, base_url: str, token: str, *, timeout: float = C.MARKETPLACE_TIMEOUT, transport=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._post = transport or _default_post

    def publish_agent(self, payload: dict) -> bool:
        """POST one agent record. Returns True on a 2xx, False on anything else
        (including network errors). Never raises."""
        url = self.base_url + INGEST_PATH
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        try:
            body = json.dumps(payload).encode("utf-8")
            status = self._post(url, headers, body, self.timeout)
            return 200 <= int(status) < 300
        except Exception:  # noqa: BLE001 - a backend problem must never break a round
            return False


def open_marketplace_client_from_env() -> MarketplaceClient | None:
    """Build a client from config, or None when it isn't configured (no-op)."""
    url = (os.getenv(C.MARKETPLACE_URL_ENV) or "").strip()
    token = (os.getenv(C.MARKETPLACE_TOKEN_ENV) or "").strip()
    if not url or not token:
        return None
    try:
        timeout = float(os.getenv(C.MARKETPLACE_TIMEOUT_ENV, C.MARKETPLACE_TIMEOUT))
    except (TypeError, ValueError):
        timeout = C.MARKETPLACE_TIMEOUT
    return MarketplaceClient(url, token, timeout=timeout)
