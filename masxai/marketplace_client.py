"""masxai/marketplace_client.py - publish qualifying agents to the marketplace.

The marketplace backend (BACKEND_FLOW.md) is a read-only catalog of the
security agents miners contribute: metadata and scores, served to a frontend.
It stores nothing it could run. The validator is the only party that knows an
agent's scores, so after scoring it pushes one record per evaluation of a
qualifying agent to `POST /api/internal/agents` (bearer token, upsert by agent
id). The backend keeps the run history and derives safe_rate / avg_requests /
variants from it, and marks an agent `stale` when pushes stop.

What may appear in a payload
----------------------------
Metadata and scores only: the agent id (the intake digest -- a hash, not a
reference), the miner's hotkey and uid (public on-chain), netuid/mechid, the
agent's self-reported name/version, the cross-category aggregate, the
per-category cells, and the run that was just scored (category, variant,
score, safe, requests, duration).

Never the blob URL, a registry image reference, the ciphertext hash, the
docker image id, layer digests, log excerpts or findings content -- anything a
peer could use to fetch, identify-and-pull, or reverse the agent.
`assert_publishable()` makes that a checked property of every outgoing payload
rather than a convention, and `build_agent_payload()` is the ONE place the
wire schema lives, so aligning field names with the backend's docs/API.md is a
single edit.

Who qualifies
-------------
`should_publish()`: an agent ENTERS when its miner's cross-category aggregate
(the same freshness-filtered mean that feeds weights) reaches
MARKETPLACE_MIN_SCORE, within a small tolerance (the aggregate is an EMA and
never lands exactly on 1.0 after an imperfect run). Once an agent id is listed,
every later evaluation of it is pushed too, so the marketplace shows the real
trajectory instead of freezing at the entry score.

Failure policy
--------------
Publishing is never allowed to affect a round. `push_agent()` has a bounded
timeout, retries 429/5xx and network errors a few times, logs, and returns
False -- it never raises. A dead backend costs nothing but a missing listing,
and the backend's own stale logic covers the gap.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import httpx

from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env

# Keys that must never appear anywhere in an outgoing payload (checked
# recursively, as substrings of key names, case-insensitive). Asserted in
# tests/test_marketplace_client.py rather than only documented.
FORBIDDEN_KEY_FRAGMENTS = (
    "blob",            # blob_url, blob_encoding
    "image",           # image_ref, image_id
    "ciphertext",
    "layer",
    "digest",          # the agent id is a digest but is sent as agent_id
    "entrypoint",
    "repo_tag",
    "log",             # log_excerpt
    "findings",
    "payload",         # a finding's injection payload
    "url",
)

# Miner-controlled display text is capped and stripped of control characters
# before it goes anywhere near a public UI.
_MAX_DISPLAY_CHARS = 64
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _display(text: Any) -> str:
    cleaned = _CONTROL_CHARS_RE.sub("", str(text or "")).strip()
    return cleaned[:_MAX_DISPLAY_CHARS]


def should_publish(
    *,
    aggregate: float,
    agent_id: Optional[str],
    listed: Iterable[str],
    min_score: float = C.MARKETPLACE_MIN_SCORE,
    tolerance: float = C.MARKETPLACE_SCORE_TOLERANCE,
) -> bool:
    """The gate. True when this agent is already listed, or when its miner's
    cross-category aggregate has reached the entry score (within tolerance).
    An agent without an id (intake never produced a digest) is never published:
    the backend upserts by id, and an unidentifiable agent is not a listing."""
    if not agent_id:
        return False
    if agent_id in set(listed):
        return True
    return float(aggregate) + float(tolerance) >= float(min_score)


def build_agent_payload(
    *,
    agent_id: str,
    miner_hotkey: str,
    miner_uid: int,
    netuid: int,
    mechid: int,
    validator_hotkey: str,
    overall_score: float,
    category_scores: dict[str, float],
    job: Any,
    evaluated_at: Optional[float] = None,
) -> dict[str, Any]:
    """The wire record for one evaluation of one agent.

    This is the ONE place the marketplace schema lives. `job` is the JobResult
    of the run just scored; only its scores and mechanics are read, never its
    raw evidence. Align the field names here with marketplace-server's
    docs/API.md; nothing else needs to change.
    """
    task = getattr(job, "task", None)
    when = datetime.fromtimestamp(
        evaluated_at if evaluated_at is not None else datetime.now(timezone.utc).timestamp(),
        tz=timezone.utc,
    )
    record = {
        "agent_id": str(agent_id),
        "miner_hotkey": str(miner_hotkey),
        "miner_uid": int(miner_uid),
        "netuid": int(netuid),
        "mechid": int(mechid),
        "validator_hotkey": str(validator_hotkey),
        "name": _display(getattr(job, "agent_name", "")),
        "version": _display(getattr(job, "agent_version", "")),
        "overall_score": round(float(overall_score), 4),
        "category_scores": {
            str(cat): round(float(score), 4)
            for cat, score in (category_scores or {}).items()
            if score is not None
        },
        "run": {
            "run_id": str(getattr(job, "run_id", "")),
            "category": str(getattr(job, "category", "") or ""),
            "variant": str(getattr(job, "variant", "") or ""),
            "score": round(float(getattr(task, "score", 0.0) or 0.0), 4) if task else 0.0,
            "safe": bool(getattr(job, "safe", False)),
            "accepted": bool(getattr(job, "accepted", False)),
            "requests": int(getattr(job, "request_count", 0) or 0),
            "duration_ms": int(getattr(job, "duration_ms", 0) or 0),
            "evaluated_at": when.isoformat(),
        },
    }
    assert_publishable(record)
    return record


def assert_publishable(payload: Any, _path: str = "") -> None:
    """Raise ValueError if any key in the payload (recursively) could carry
    something a peer could use to fetch or reverse the agent."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = str(key).lower()
            for fragment in FORBIDDEN_KEY_FRAGMENTS:
                if fragment in lowered:
                    raise ValueError(
                        f"marketplace payload must not carry {_path}{key!r} "
                        f"(matches forbidden fragment {fragment!r})"
                    )
            assert_publishable(value, f"{_path}{key}.")
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            assert_publishable(item, _path)


class MarketplaceClient:
    """Pushes agent records to the marketplace backend. Never raises."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout: float = C.MARKETPLACE_TIMEOUT,
        max_retries: int = C.MARKETPLACE_MAX_RETRIES,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not base_url:
            raise ValueError("marketplace base_url is required")
        if not token:
            raise ValueError(f"marketplace token is required; set {C.MARKETPLACE_TOKEN_ENV}")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = float(timeout)
        self.max_retries = max(1, int(max_retries))
        self._transport = transport  # tests inject httpx.MockTransport

    async def push_agent(self, payload: dict[str, Any]) -> bool:
        """POST one record. True only on a 2xx. Logs and returns False on
        anything else -- a push must never break the round that produced it."""
        try:
            assert_publishable(payload)
        except ValueError as e:
            # A programming error, not a network one: refuse loudly in logs,
            # but still never raise into the round.
            bt.logging.error(f"marketplace: refusing to publish: {e}")
            return False

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout, transport=self._transport
            ) as client:
                for attempt in range(1, self.max_retries + 1):
                    try:
                        resp = await client.post(
                            C.MARKETPLACE_AGENTS_PATH, content=body, headers=headers
                        )
                    except httpx.RequestError as e:
                        if attempt >= self.max_retries:
                            bt.logging.warning(
                                f"marketplace: network error after {attempt} attempt(s): {e!r}"
                            )
                            return False
                        await _backoff(attempt)
                        continue
                    if 200 <= resp.status_code < 300:
                        return True
                    if resp.status_code == 429 or resp.status_code >= 500:
                        if attempt < self.max_retries:
                            await _backoff(attempt, resp)
                            continue
                    # 4xx (other than 429), or retries exhausted. The body is
                    # the backend's explanation; the token is never logged.
                    bt.logging.warning(
                        f"marketplace: push rejected with HTTP {resp.status_code} "
                        f"after {attempt} attempt(s): {resp.text[:200]}"
                    )
                    return False
        except Exception as e:  # noqa: BLE001 -- must never break a caller
            bt.logging.warning(f"marketplace: push failed: {e}")
        return False


async def _backoff(attempt: int, response: Optional[httpx.Response] = None) -> None:
    import asyncio

    retry_after = response.headers.get("Retry-After") if response is not None else None
    if retry_after:
        try:
            await asyncio.sleep(min(max(0.0, float(retry_after)), 5.0))
            return
        except ValueError:
            pass
    await asyncio.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))


def open_marketplace_client_from_env() -> Optional[MarketplaceClient]:
    """Returns None when unconfigured -- the feature's kill switch. The
    validator must never push when this is None."""
    load_env()
    base_url = (os.getenv(C.MARKETPLACE_BASE_URL_ENV, "") or "").strip()
    token = (os.getenv(C.MARKETPLACE_TOKEN_ENV, "") or "").strip()
    if not base_url or not token:
        return None
    return MarketplaceClient(
        base_url=base_url,
        token=token,
        timeout=_env_float(C.MARKETPLACE_TIMEOUT_ENV, C.MARKETPLACE_TIMEOUT),
    )


# --- the listed-agents memory -----------------------------------------

def load_listed(path: str) -> set[str]:
    """Agent ids this validator has already listed. Empty when the file is
    absent or unreadable -- the only cost is that an already-listed agent
    waits for its aggregate to qualify again before pushes resume."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        ids = data.get("listed", []) if isinstance(data, dict) else data
        return {str(x) for x in ids} if isinstance(ids, list) else set()
    except (FileNotFoundError, ValueError, OSError):
        return set()


def save_listed(path: str, listed: Iterable[str]) -> None:
    """Best-effort atomic write; a failed save never takes the validator down."""
    try:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"listed": sorted(set(listed))}, fh)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 - persistence is best-effort
        pass


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
