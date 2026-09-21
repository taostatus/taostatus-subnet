from __future__ import annotations

"""HTTP client for the protocol backend's /llm-keys/* endpoints.

Bearer-token auth, retry/backoff on 429/5xx, Pydantic response models, and an
open_llm_key_client_from_env() factory that returns None when unconfigured --
which doubles as this feature's validator-side kill switch.
"""

import asyncio
import json
import os
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, Field

from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env


class LLMKeyPublicKey(BaseModel):
    pubkey_id: str
    pubkey_b64: str
    algo: str = "nacl-sealedbox-v1"


class LLMKeyAllowedModel(BaseModel):
    provider: str
    model: str


class LLMKeySubmitKeyResult(BaseModel):
    """Per-key outcome of one slot in a batch submission."""

    slot: int
    key_id: Optional[int] = None  # stable backend row id, set when accepted
    provider: str = ""
    model: str = ""
    accepted: bool
    status: str
    reason: Optional[str] = None


class LLMKeySubmitResult(BaseModel):
    accepted: bool  # aggregate: at least one key accepted
    status: str
    reason: Optional[str] = None
    results: list[LLMKeySubmitKeyResult] = Field(default_factory=list)


class LLMKeyUsageReport(BaseModel):
    hotkey: str
    # Which of the hotkey's keys served this call. The validator blends
    # reward tiers per call from provider/model and kills per key_id. None
    # only on rows written before the backend's multi-key migration.
    key_id: Optional[int] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0
    avg_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    avg_quality_score: Optional[float] = None
    error_categories: dict[str, Any] = Field(default_factory=dict)
    key_active: bool = True
    created_at: Optional[str] = None


class LLMKeyRosterEntry(BaseModel):
    """One KEY's current status (a multi-key hotkey appears once per slot),
    from GET /llm-keys/roster -- a precise, near-real-time signal (validator
    polls it every report-poll cycle) for DEAD/REVOKED transitions. Anything
    this can't see (e.g. a transient outage between validator and protocol)
    stops earning at the next epoch reset anyway, since scores never carry
    over."""

    hotkey: str
    key_id: Optional[int] = None
    slot: int = 0
    provider: Optional[str] = None
    model: Optional[str] = None
    status: str
    status_reason: Optional[str] = None
    updated_at: Optional[str] = None


class LLMKeyClient:
    def __init__(
        self,
        *,
        base_url: str,
        validator_token: str = "",
        timeout: float = C.LLM_KEY_TIMEOUT,
        max_retries: int = C.LLM_KEY_MAX_RETRIES,
    ) -> None:
        if not base_url:
            raise ValueError("LLM-key protocol base_url is required")
        if not validator_token:
            raise ValueError(
                "LLM-key protocol validator_token is required; "
                f"set {C.LLM_KEY_VALIDATOR_TOKEN_ENV}"
            )
        self.base_url = base_url.rstrip("/")
        self.validator_token = validator_token
        self.timeout = timeout
        connect_timeout = min(
            timeout, _env_float(C.LLM_KEY_CONNECT_TIMEOUT_ENV, C.LLM_KEY_CONNECT_TIMEOUT)
        )
        self._httpx_timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self.max_retries = max(1, max_retries)
        self._client: Optional[httpx.AsyncClient] = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            async with self._client_lock:
                if self._client is None or self._client.is_closed:
                    self._client = httpx.AsyncClient(
                        base_url=self.base_url, timeout=self._httpx_timeout
                    )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_public_key(self) -> LLMKeyPublicKey:
        payload = await self._request_json("GET", "/llm-keys/public-key")
        return LLMKeyPublicKey.model_validate(payload)

    async def get_allowed_models(self) -> list[LLMKeyAllowedModel]:
        payload = await self._request_json("GET", "/llm-keys/allowed-models")
        return [
            LLMKeyAllowedModel.model_validate(item)
            for item in payload.get("models", [])
            if isinstance(item, dict)
        ]

    async def submit_keys(
        self,
        *,
        hotkey: str,
        uid: Optional[int],
        keys: list[dict[str, Any]],
    ) -> LLMKeySubmitResult:
        """Relay a miner's key batch (each entry: slot, provider, model,
        encrypted_key_blob, blob_encoding, pubkey_id_used) in one round trip.
        The backend answers per-key results plus a legacy aggregate."""
        payload = await self._request_json(
            "POST",
            "/llm-keys/submit",
            json_body={
                "hotkey": hotkey,
                "uid": uid,
                "keys": keys,
            },
        )
        return LLMKeySubmitResult.model_validate(payload)

    async def get_reports(
        self, *, since: Optional[str] = None,
    ) -> tuple[list[LLMKeyUsageReport], Optional[str]]:
        query = f"?{urlencode({'since': since})}" if since else ""
        payload = await self._request_json("GET", f"/llm-keys/reports{query}")
        reports = [
            LLMKeyUsageReport.model_validate(item)
            for item in payload.get("reports", [])
            if isinstance(item, dict)
        ]
        next_since = payload.get("next_since")
        return reports, next_since

    async def get_key_statuses(self) -> list[LLMKeyRosterEntry]:
        payload = await self._request_json("GET", "/llm-keys/roster")
        return [
            LLMKeyRosterEntry.model_validate(item)
            for item in payload.get("entries", [])
            if isinstance(item, dict)
        ]

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
    ) -> Any:
        body = b""
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), sort_keys=True).encode("utf-8")

        client = await self._get_client()
        for attempt in range(1, self.max_retries + 1):
            headers = self._auth_headers()
            if body:
                headers["Content-Type"] = "application/json"
            try:
                response = await client.request(
                    method,
                    path,
                    headers=headers,
                    content=body if body else None,
                )
                if response.status_code == 429 or 500 <= response.status_code < 600:
                    if attempt < self.max_retries:
                        await _sleep_for_retry(response=response, attempt=attempt)
                        continue
                    bt.logging.warning(
                        f"llm-key client: backend persistently erroring after {attempt} "
                        f"attempt(s) ({method} {path} -> HTTP {response.status_code})"
                    )
                response.raise_for_status()
                if not response.content:
                    return {}
                return response.json()
            except httpx.RequestError as e:
                if attempt >= self.max_retries:
                    bt.logging.warning(
                        f"llm-key client: network error after {attempt} attempt(s) "
                        f"({method} {path}): {e!r}"
                    )
                    raise
                await _sleep_for_retry(response=None, attempt=attempt)
        return {}

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.validator_token:
            headers["X-Validator-Key"] = self.validator_token
        return headers


def open_llm_key_client_from_env() -> Optional[LLMKeyClient]:
    """Returns None when unconfigured -- this is the feature's validator-side
    kill switch. Callers must never invoke the submission/report-poll rounds
    when this is None."""
    load_env()
    validator_token = os.getenv(C.LLM_KEY_VALIDATOR_TOKEN_ENV, "").strip()
    if not validator_token:
        return None
    base_url = os.getenv(C.LLM_KEY_BASE_URL_ENV, "").strip()
    if not base_url:
        return None
    return LLMKeyClient(
        base_url=base_url,
        validator_token=validator_token,
        timeout=_env_float(C.LLM_KEY_TIMEOUT_ENV, C.LLM_KEY_TIMEOUT),
        max_retries=_env_int(C.LLM_KEY_MAX_RETRIES_ENV, C.LLM_KEY_MAX_RETRIES),
    )


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


async def _sleep_for_retry(*, response: Optional[httpx.Response], attempt: int) -> None:
    retry_after = response.headers.get("Retry-After") if response is not None else None
    if retry_after:
        try:
            delay = max(0.0, float(retry_after))
            ceiling = _env_float(
                C.LLM_KEY_RETRY_AFTER_MAX_SECONDS_ENV, C.LLM_KEY_RETRY_AFTER_MAX_SECONDS
            )
            await asyncio.sleep(min(delay, ceiling))
            return
        except ValueError:
            pass
    await asyncio.sleep(min(3.0, 0.25 * (2 ** (attempt - 1))))
