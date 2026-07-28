"""
neurons/miner.py - MASXAI MVP miner.

Miners use Gemini as the forecasting engine when GEMINI_API_KEY or GOOGLE_API_KEY
is configured. Without a key, the miner still serves a neutral baseline forecast
so local runs and testnet smoke tests do not require secrets.
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
from masxai.gemini import baseline_forecast, generate_forecast

# Provided by the bittensor-subnet-template fork:
try:
    from template.base.miner import BaseMinerNeuron
except Exception:
    class BaseMinerNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseMinerNeuron requires a working bittensor install")


def predict(synapse: ForecastSynapse) -> dict:
    """
    Baseline structured forecast. Kept as a simple override point for custom
    miners and for the local mock runner.
    """
    return baseline_forecast(synapse)


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


class Miner(BaseMinerNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        gemini_key_set = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        bt.logging.info(
            "Gemini config | "
            f"enabled={_env_flag('GEMINI_ENABLED', True)} "
            f"key_set={gemini_key_set} "
            f"model={os.getenv('GEMINI_MODEL', C.GEMINI_MODEL)} "
            f"timeout={os.getenv('GEMINI_TIMEOUT', C.GEMINI_TIMEOUT)}"
        )
        bt.logging.info("MASXAI v1 baseline miner initialized.")

    async def forward(self, synapse: ForecastSynapse) -> ForecastSynapse:
        """Answer a forecasting question with a structured Gemini forecast."""
        try:
            forecast = await generate_forecast(synapse)
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"miner predict failed, returning neutral: {e}")
            forecast = predict(synapse)

        synapse.forecast_id = str(forecast.get("forecast_id") or synapse.forecast_id)
        synapse.prediction = forecast.get("prediction")
        synapse.confidence = forecast.get("confidence")
        synapse.reasoning = str(forecast.get("reasoning") or "")
        synapse.timestamp = str(forecast.get("timestamp") or "")
        synapse.model = str(forecast.get("model") or C.GEMINI_MODEL)

        if synapse.prediction is not None and synapse.confidence is not None:
            synapse.probability = (
                float(synapse.confidence)
                if synapse.prediction
                else 1.0 - float(synapse.confidence)
            )

        asyncio.create_task(publish_forecast(forecast))
        bt.logging.debug(
            f"answered: event={synapse.event_type} prediction={synapse.prediction} "
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
        # In v1 we only require registration. To restrict to validators, also check:
        #   if not self.metagraph.validator_permit[uid]: return True, "no validator permit"
        return False, f"accepted from uid {uid}"

    async def priority(self, synapse: ForecastSynapse) -> float:
        """Prioritize higher-stake callers. Standard template pattern."""
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return 0.0
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        return float(self.metagraph.S[uid])


def _exit_if_worker_stopped(miner: Miner) -> None:
    thread = getattr(miner, "thread", None)
    if thread is None:
        bt.logging.error(
            "miner worker was not started; exiting for supervisor restart"
        )
        raise SystemExit(1)
    if thread.is_alive():
        return

    err = getattr(miner, "run_exception", None)
    if err is not None:
        bt.logging.error(
            f"miner worker stopped after fatal error; exiting for supervisor restart: {err}"
        )
    else:
        bt.logging.error(
            "miner worker stopped unexpectedly; exiting for supervisor restart"
        )
    raise SystemExit(1)


if __name__ == "__main__":
    with Miner() as miner:
        next_heartbeat_at = 0.0
        while True:
            _exit_if_worker_stopped(miner)
            now = time.time()
            if now >= next_heartbeat_at:
                bt.logging.info(
                    f"MASXAI miner alive | {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                next_heartbeat_at = now + 30
            time.sleep(1)
