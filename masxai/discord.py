"""
Discord webhook publishing for miner forecast summaries.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env


def format_forecast_message(forecast: Dict[str, Any]) -> str:
    event = str(forecast.get("event_type", "unknown")).replace("_", " ").title()
    prediction = forecast.get("prediction")
    probability = forecast.get("probability")
    no_answer = prediction is None and probability is None
    outlook = (
        "No forecast"
        if no_answer
        else "Upward / YES" if prediction is True else "Downward / NO"
    )
    confidence = float(forecast.get("confidence") or 0.0)
    confidence_text = "N/A" if no_answer else f"{confidence:.0%}"
    window = str(forecast.get("forecast_window") or "unknown")
    model = str(forecast.get("model") or "Gemini")
    forecast_id = str(forecast.get("forecast_id", ""))[:8]
    reasoning = str(forecast.get("reasoning") or "No reasoning supplied.").strip()
    if len(reasoning) > 320:
        reasoning = reasoning[:317] + "..."

    if model == "baseline-after-gemini-error":
        source = "Gemini fallback"
    elif model == "baseline-gemini-disabled":
        source = "Baseline fallback (Gemini disabled)"
    elif model == "baseline":
        source = "Baseline fallback (Gemini not configured)"
    else:
        source = model

    return (
        "**MASXAI Forecast Brief**\n"
        f"`#{forecast_id}`\n\n"
        f"**Market/Event:** {event}\n"
        f"**Outlook:** {outlook}\n"
        f"**Confidence:** {confidence_text}\n"
        f"**Forecast Window:** {window}\n"
        f"**Source:** {source}\n\n"
        f"**Why it matters:** {reasoning}"
    )


async def publish_forecast(
    forecast: Dict[str, Any],
    webhook_url: Optional[str] = None,
) -> bool:
    """Post a forecast summary to Discord. Returns False on any soft failure."""
    load_env()
    webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        return False

    try:
        async with httpx.AsyncClient(timeout=C.DISCORD_TIMEOUT) as client:
            resp = await client.post(
                webhook_url,
                json={"content": format_forecast_message(forecast)},
            )
            resp.raise_for_status()
        return True
    except Exception as e:  # noqa: BLE001 - Discord must not break mining
        bt.logging.warning(f"Discord publish failed: {e}")
        return False
