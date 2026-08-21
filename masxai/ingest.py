from __future__ import annotations

"""HTTP client for the Miner Forecast Ingestion API.

A separate backend from any other integration: it accepts machine-to-machine
reports of miner metagraph state and forecast activity, authenticated with a
static X-API-Key header rather than a bearer token. Entirely optional -
validators that don't configure it never call out to it.
"""

import asyncio
import json
import os
from typing import Any, Optional
from urllib.parse import quote

import httpx

from masxai import constants as C
from masxai.env import load_env


class IngestClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: float = C.INGEST_TIMEOUT,
        max_retries: int = C.INGEST_MAX_RETRIES,
    ) -> None:
        if not base_url:
            raise ValueError("ingest base_url is required")
        if not api_key:
            raise ValueError("ingest api_key is required; set INGEST_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max(1, max_retries)

    async def upsert_miner(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request_json("POST", "/api/miners", json_body=payload)

    async def submit_activity(self, hotkey: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request_json(
            "POST",
            f"/api/miners/{quote(hotkey)}/activities",
            json_body=payload,
        )

    async def resolve_activity(
        self,
        hotkey: str,
        activity_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._request_json(
            "PATCH",
            f"/api/miners/{quote(hotkey)}/activities/{quote(activity_id)}/resolve",
            json_body=payload,
        )

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        body = b""
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), sort_keys=True).encode("utf-8")

        for attempt in range(1, self.max_retries + 1):
            headers = self._auth_headers()
            if body:
                headers["Content-Type"] = "application/json"
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self.timeout,
                ) as client:
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
                response.raise_for_status()
                if not response.content:
                    return {}
                return response.json()
            except httpx.RequestError:
                if attempt >= self.max_retries:
                    raise
                await _sleep_for_retry(response=None, attempt=attempt)
        return {}

    def _auth_headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key}


def open_ingest_client_from_env() -> Optional[IngestClient]:
    load_env()
    api_key = os.getenv(C.INGEST_API_KEY_ENV, "").strip()
    base_url = os.getenv(C.INGEST_BASE_URL_ENV, "").strip()
    if not api_key or not base_url:
        return None
    return IngestClient(
        base_url=base_url,
        api_key=api_key,
        timeout=_env_float(C.INGEST_TIMEOUT_ENV, C.INGEST_TIMEOUT),
        max_retries=_env_int(C.INGEST_MAX_RETRIES_ENV, C.INGEST_MAX_RETRIES),
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
            await asyncio.sleep(max(0.0, float(retry_after)))
            return
        except ValueError:
            pass
    await asyncio.sleep(min(3.0, 0.25 * (2 ** (attempt - 1))))
