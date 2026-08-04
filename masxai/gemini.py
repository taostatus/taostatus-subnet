"""
Gemini integration for MASXAI miners.

This module calls the Gemini REST API directly through httpx so miners do not
need a heavyweight SDK. Missing API keys or invalid responses degrade to a
structured no-answer fallback instead of crashing the miner.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.protocol import ForecastSynapse
from masxai.scoring import clamp_confidence


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def baseline_forecast(
    synapse: ForecastSynapse,
    model: str = "baseline",
    reasoning: str = "No forecast returned; Gemini is not configured.",
) -> Dict[str, Any]:
    """Return a valid no-answer payload when Gemini is unavailable."""
    return {
        "forecast_id": synapse.forecast_id,
        "event_type": synapse.event_type,
        "prediction": None,
        "confidence": None,
        "probability": None,
        "forecast_window": synapse.forecast_window,
        "reasoning": reasoning,
        "timestamp": utc_now_iso(),
        "model": model,
    }


def _extract_json(text: str) -> Dict[str, Any]:
    """Parse a JSON object from plain text or a fenced Gemini response."""
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    elif "{" in text and "}" in text:
        text = text[text.index("{") : text.rindex("}") + 1]
    return json.loads(text)


def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"yes", "true", "1", "up", "higher"}:
            return True
        if lowered in {"no", "false", "0", "down", "lower"}:
            return False
    return None


def sanitize_forecast(raw: Dict[str, Any], synapse: ForecastSynapse, model: str) -> Dict[str, Any]:
    probability_raw = raw.get("probability")
    probability = None
    if probability_raw is not None:
        probability = max(0.0, min(1.0, float(probability_raw)))

    prediction = _coerce_bool(raw.get("prediction"))
    if prediction is None and probability is not None:
        prediction = probability >= 0.5
    if prediction is None:
        raise ValueError("Gemini response did not include a boolean prediction or probability")

    confidence = clamp_confidence(float(raw.get("confidence", 0.5)))
    if probability is None:
        probability = confidence if prediction else 1.0 - confidence
    reasoning = str(raw.get("reasoning", "")).strip()
    if len(reasoning) > 600:
        reasoning = reasoning[:597] + "..."

    return {
        "forecast_id": str(raw.get("forecast_id") or synapse.forecast_id),
        "event_type": str(raw.get("event_type") or synapse.event_type),
        "prediction": prediction,
        "confidence": confidence,
        "probability": probability,
        "forecast_window": str(raw.get("forecast_window") or synapse.forecast_window),
        "reasoning": reasoning or "No reasoning supplied.",
        "timestamp": str(raw.get("timestamp") or utc_now_iso()),
        "model": str(raw.get("model") or model),
        "features": dict(raw.get("features") or {}),
    }


def build_prompt(synapse: ForecastSynapse) -> str:
    schema = {
        "forecast_id": synapse.forecast_id,
        "event_type": synapse.event_type,
        "prediction": True,
        "confidence": 0.0,
        "probability": 0.0,
        "forecast_window": synapse.forecast_window,
        "reasoning": "short evidence-based summary",
        "features": {"signal_name": "optional value"},
        "timestamp": utc_now_iso(),
    }
    return (
        "You are a forecasting miner on the MASXAI Bittensor subnet.\n"
        "Return only valid JSON matching this schema, with no markdown.\n"
        f"{json.dumps(schema)}\n\n"
        "Forecast metadata:\n"
        f"family={synapse.family or synapse.event_type}\n"
        f"scope={synapse.scope or 'unknown'}\n"
        f"netuid={synapse.netuid if synapse.netuid is not None else 'n/a'}\n"
        f"horizon_days={synapse.horizon_days if synapse.horizon_days is not None else 'n/a'}\n\n"
        "Forecast question:\n"
        f"{synapse.question}\n\n"
        "Context:\n"
        f"{synapse.context or 'No additional context supplied.'}\n\n"
        "Rules:\n"
        "- prediction must be boolean.\n"
        "- probability must be your calibrated P(YES) between 0 and 1.\n"
        "- confidence must be a calibrated number between 0 and 1.\n"
        "- reasoning must be concise and must not claim certainty.\n"
    )


def _format_exception(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        body = e.response.text[:300] if e.response is not None else ""
        return f"{type(e).__name__}: status={e.response.status_code} body={body}"
    return f"{type(e).__name__}: {repr(e)}"


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _gemini_timeout() -> float:
    try:
        return float(os.getenv("GEMINI_TIMEOUT", C.GEMINI_TIMEOUT))
    except ValueError:
        return float(C.GEMINI_TIMEOUT)


async def generate_forecast(
    synapse: ForecastSynapse,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a structured forecast with Gemini, falling back on baseline."""
    load_env()
    if not _env_flag("GEMINI_ENABLED", default=True):
        return baseline_forecast(
            synapse,
            model="baseline-gemini-disabled",
            reasoning="No forecast returned; Gemini is disabled in .env.",
        )

    api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    model = model or os.getenv("GEMINI_MODEL", C.GEMINI_MODEL)
    if not api_key:
        return baseline_forecast(
            synapse,
            reasoning="No forecast returned; Gemini API key is not configured.",
        )

    url = C.GEMINI_API_URL.format(model=model)
    payload = {
        "contents": [{"role": "user", "parts": [{"text": build_prompt(synapse)}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    try:
        async with httpx.AsyncClient(timeout=_gemini_timeout()) as client:
            resp = await client.post(url, params={"key": api_key}, json=payload)
            resp.raise_for_status()
            data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return sanitize_forecast(_extract_json(text), synapse, model)
    except Exception as e:  # noqa: BLE001 - miners must keep serving forecasts
        error = _format_exception(e)
        bt.logging.warning(f"Gemini forecast failed; using baseline: {error}")
        return baseline_forecast(
            synapse,
            model="baseline-after-gemini-error",
            reasoning=(
                "No forecast returned because Gemini was configured but "
                f"the request failed: {error}"
            ),
        )
