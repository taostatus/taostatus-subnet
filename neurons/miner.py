"""
neurons/miner.py - MASXAI MVP miner.

Miners use Gemini as the forecasting engine when GEMINI_API_KEY or GOOGLE_API_KEY
is configured. Without a usable Gemini response, the miner returns a structured
no-answer payload so it stays online without earning forecast credit.
"""

import os
import sys
import asyncio
import time
import typing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import ForecastSynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.discord import publish_forecast
from masxai.env import load_env
from masxai.gemini import baseline_forecast, generate_forecast, gemini_timeout

# Provided by the bittensor-subnet-template fork:
try:
    from template.base.miner import BaseMinerNeuron
except Exception:
    class BaseMinerNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseMinerNeuron requires a working bittensor install")


def predict(synapse: ForecastSynapse) -> dict:
    """
    Structured no-answer fallback. Kept as a simple override point for custom
    miners and for the local mock runner.
    """
    return baseline_forecast(synapse)


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _timeout_margin_warning(resolved_timeout: float) -> typing.Optional[str]:
    """Warn when GEMINI_TIMEOUT leaves too little room under QUERY_TIMEOUT.

    A slow-but-successful Gemini call needs time to serialize and cross the
    wire before the validator's dendrite call gives up; without margin that
    looks identical to "the miner never answered."
    """
    margin = C.QUERY_TIMEOUT - resolved_timeout
    if margin >= C.GEMINI_TIMEOUT_MARGIN_SECONDS:
        return None
    safe_max = C.QUERY_TIMEOUT - C.GEMINI_TIMEOUT_MARGIN_SECONDS
    return (
        f"GEMINI_TIMEOUT={resolved_timeout}s leaves only {margin:.1f}s of margin "
        f"under the validator's QUERY_TIMEOUT={C.QUERY_TIMEOUT}s; a slow Gemini "
        "call may never make it back to the validator in time and will be "
        f"scored as a no-answer. Recommend GEMINI_TIMEOUT <= {safe_max}s."
    )


class Miner(BaseMinerNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        gemini_key_set = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        resolved_gemini_timeout = gemini_timeout()
        bt.logging.info(
            "Gemini config | "
            f"enabled={_env_flag('GEMINI_ENABLED', True)} "
            f"key_set={gemini_key_set} "
            f"model={os.getenv('GEMINI_MODEL', C.GEMINI_MODEL)} "
            f"timeout={resolved_gemini_timeout}"
        )
        margin_warning = _timeout_margin_warning(resolved_gemini_timeout)
        if margin_warning:
            bt.logging.warning(margin_warning)
        bt.logging.info("MASXAI v1 Gemini miner initialized.")

    async def forward(self, synapse: ForecastSynapse) -> ForecastSynapse:
        """Answer a forecasting question with a structured Gemini forecast."""
        try:
            forecast = await generate_forecast(synapse)
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"miner predict failed, returning no-answer: {e}")
            forecast = predict(synapse)

        synapse.forecast_id = str(forecast.get("forecast_id") or synapse.forecast_id)
        synapse.prediction = forecast.get("prediction")
        synapse.confidence = forecast.get("confidence")
        synapse.probability = forecast.get("probability")
        synapse.reasoning = str(forecast.get("reasoning") or "")
        synapse.timestamp = str(forecast.get("timestamp") or "")
        synapse.model = str(forecast.get("model") or C.GEMINI_MODEL)
        synapse.features = dict(forecast.get("features") or {})

        if (
            synapse.probability is None
            and synapse.prediction is not None
            and synapse.confidence is not None
        ):
            synapse.probability = (
                float(synapse.confidence)
                if synapse.prediction
                else 1.0 - float(synapse.confidence)
            )

        if synapse.probability is not None:
            asyncio.create_task(publish_forecast(forecast))
        status = "no-answer" if synapse.probability is None else "answered"
        bt.logging.debug(
            f"{status}: event={synapse.event_type} model={synapse.model} "
            f"probability={synapse.probability} prediction={synapse.prediction} "
            f"confidence={synapse.confidence}"
        )
        return synapse

    async def blacklist(self, synapse: ForecastSynapse) -> typing.Tuple[bool, str]:
        """
        Reject requests from non-registered or (optionally) non-validator hotkeys.
        Keeps the axon from answering spam. Standard template pattern.
        """
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return True, "missing dendrite/hotkey"

        hotkey = synapse.dendrite.hotkey
        if hotkey not in self.metagraph.hotkeys:
            return True, f"unregistered hotkey {hotkey}"

        uid = self.metagraph.hotkeys.index(hotkey)
        # Two ways to require a validator permit: the standard bittensor-template
        # CLI flag (--blacklist.force_validator_permit) and this project's own
        # MASXAI_REQUIRE_VALIDATOR_PERMIT env var. Previously only the env var
        # was honored here, so the CLI flag silenced the base class's security
        # warning without actually enforcing anything - honor either.
        require_permit = bool(
            getattr(getattr(self.config, "blacklist", None), "force_validator_permit", False)
        ) or _env_flag(C.MINER_REQUIRE_VALIDATOR_PERMIT_ENV, False)
        if require_permit:
            permits = getattr(self.metagraph, "validator_permit", None)
            if permits is None:
                return True, "validator permit unavailable"
            if not bool(permits[uid]):
                return True, "no validator permit"
        return False, f"accepted from uid {uid}"

    async def priority(self, synapse: ForecastSynapse) -> float:
        """Prioritize higher-stake callers. Standard template pattern."""
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return 0.0
        try:
            uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        except ValueError:
            return 0.0
        return float(self.metagraph.S[uid])


if __name__ == "__main__":
    with Miner() as miner:
        while True:
            bt.logging.info(f"MASXAI miner alive | {time.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(30)
