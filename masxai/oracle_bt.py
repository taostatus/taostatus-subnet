from __future__ import annotations

"""HTTP client for the centralized BT-Forecast FastAPI service.

The subnet treats the private service as the source of miner-safe questions and
real outcomes. Validators relay questions to miners over the synapse; miners
never call this API and never receive service-only benchmark fields.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any, Optional
from urllib.parse import quote, urlencode

import httpx
from pydantic import BaseModel, Field

from masxai import constants as C
from masxai.env import load_env


class BtForecastRunStatus(BaseModel):
    run_id: str
    status: str
    generation: Optional[str] = None
    created_at: Optional[str] = None
    ready_at: Optional[str] = None
    question_count: Optional[int] = None
    template_version: Optional[str] = None
    measurement_version: Optional[str] = None
    poll_after_s: Optional[int] = None


class BtForecastQuestion(BaseModel):
    question_id: str = ""
    question_key: str
    question: str
    family: str = ""
    scope: str = ""
    netuid: Optional[int] = None
    horizon_days: Optional[int] = None
    generated_at: Optional[str] = None
    cutoff_date: str
    resolution_criteria: str = ""
    evidence_summary: str = ""
    measurement: dict[str, Any] = Field(default_factory=dict)

    # Validator-only lineage fields. These must never be copied into the synapse.
    engine_probability: Optional[float] = None
    anchor_probability: Optional[float] = None
    chain_probability: Optional[float] = None
    llm_probability: Optional[float] = None
    predetermined_at_creation: bool = False


class BtForecastResolution(BaseModel):
    question_key: str
    family: str = ""
    scope: str = ""
    netuid: Optional[int] = None
    horizon_days: Optional[int] = None
    status: str
    outcome: Optional[bool] = None
    cutoff_date: Optional[str] = None
    resolved_at: Optional[str] = None
    measurement: dict[str, Any] = Field(default_factory=dict)
    measurement_value: Any = None
    observed_at: Optional[str] = None
    explanation: Optional[str] = None
    engine_brier: Optional[float] = None
    deferral_reason: Optional[str] = None

    def is_resolved(self) -> bool:
        return self.status in {C.BT_FORECAST_RESOLVED_TRUE, C.BT_FORECAST_RESOLVED_FALSE}

    def bool_outcome(self) -> Optional[bool]:
        if self.outcome is not None:
            return bool(self.outcome)
        if self.status == C.BT_FORECAST_RESOLVED_TRUE:
            return True
        if self.status == C.BT_FORECAST_RESOLVED_FALSE:
            return False
        return None


class BtForecastAdvisory(BaseModel):
    prediction_id: str = ""
    stakeholder_type: str = ""
    recommendation: str = ""
    urgency: str = ""
    on_chain_basis: str = ""
    trigger_threshold: str = ""
    invalidation_threshold: str = ""


class BtForecastClient:
    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str = "",
        timeout: float = C.BT_FORECAST_TIMEOUT,
        max_retries: int = C.BT_FORECAST_MAX_RETRIES,
    ) -> None:
        if not base_url:
            raise ValueError("BT-Forecast base_url is required")
        if not bearer_token:
            raise ValueError(
                "BT-Forecast bearer_token is required; set BT_FORECAST_BEARER_TOKEN"
            )
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.max_retries = max(1, max_retries)

    async def start_run(self, *, date: str, force: bool = False) -> BtForecastRunStatus:
        payload = await self._request_json(
            "POST",
            "/v1/forecast-runs",
            json_body={"date": date, "force": force},
        )
        return BtForecastRunStatus.model_validate(payload)

    async def get_run(self, run_id: str) -> BtForecastRunStatus:
        payload = await self._request_json("GET", f"/v1/forecast-runs/{quote(run_id)}")
        return BtForecastRunStatus.model_validate(payload)

    async def get_questions(
        self,
        run_id: str,
        *,
        include_lineage: bool = False,
    ) -> list[BtForecastQuestion]:
        query = "?include=lineage" if include_lineage else ""
        payload = await self._request_json(
            "GET",
            f"/v1/forecast-runs/{quote(run_id)}/questions{query}",
        )
        return [
            BtForecastQuestion.model_validate(item)
            for item in payload.get("questions", [])
            if isinstance(item, dict)
        ]

    async def get_resolutions(
        self,
        *,
        run_id: str,
        since: Optional[str] = None,
    ) -> list[BtForecastResolution]:
        params = {"run_id": run_id}
        if since:
            params["since"] = since
        payload = await self._request_json("GET", f"/v1/resolutions?{urlencode(params)}")
        return [
            BtForecastResolution.model_validate(item)
            for item in payload.get("resolutions", [])
            if isinstance(item, dict)
        ]

    async def get_advisories(self, *, run_id: str) -> list[BtForecastAdvisory]:
        payload = await self._request_json(
            "GET",
            f"/v1/advisories?{urlencode({'run_id': run_id})}",
        )
        return [
            BtForecastAdvisory.model_validate(item)
            for item in payload.get("advisories", [])
            if isinstance(item, dict)
        ]

    async def post_miner_results(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = await self._request_json("POST", "/v1/miner-results", json_body=payload)
        return result if isinstance(result, dict) else {}

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
        headers: dict[str, str] = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers


def open_bt_forecast_client_from_env() -> Optional[BtForecastClient]:
    load_env()
    bearer_token = os.getenv(C.BT_FORECAST_BEARER_TOKEN_ENV, "").strip()
    if not bearer_token:
        return None
    base_url = os.getenv(C.BT_FORECAST_BASE_URL_ENV, "").strip()
    return BtForecastClient(
        base_url=base_url or C.BT_FORECAST_DEFAULT_BASE_URL,
        bearer_token=bearer_token,
        timeout=_env_float("BT_FORECAST_TIMEOUT", C.BT_FORECAST_TIMEOUT),
        max_retries=_env_int("BT_FORECAST_MAX_RETRIES", C.BT_FORECAST_MAX_RETRIES),
    )


def bt_forecast_required_from_env() -> bool:
    load_env()
    return _env_bool(C.BT_FORECAST_REQUIRED_ENV, False)


def bt_forecast_run_id_from_env(now: Optional[datetime] = None) -> str:
    load_env()
    configured = os.getenv(C.BT_FORECAST_RUN_ID_ENV, "").strip()
    if configured:
        return configured
    configured_date = os.getenv(C.BT_FORECAST_RUN_DATE_ENV, "").strip()
    if configured_date:
        return f"bt-{configured_date}"
    now = now or datetime.now(timezone.utc)
    return f"bt-{now.date().isoformat()}"


def parse_api_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_api_timestamp(value: Optional[str]) -> Optional[float]:
    parsed = parse_api_datetime(value)
    return parsed.timestamp() if parsed else None


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
