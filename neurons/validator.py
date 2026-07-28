"""
neurons/validator.py - MASXAI MVP validator.

The validator issues structured forecasting tasks, stores miner forecasts, waits
for the forecast window to complete, resolves ground truth through objective
oracles, scores miners, and lets the template weight machinery use self.scores.
"""

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime
from typing import Optional

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import ForecastSynapse, ForecastEventType
from masxai import constants as C
from masxai import oracle
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.scoring import ema_update, score_structured_forecast

try:
    from template.base.validator import BaseValidatorNeuron
except Exception:
    class BaseValidatorNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseValidatorNeuron requires a working bittensor install")


def _parse_timestamp(value: str) -> Optional[float]:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _env_float(name: str, default: float) -> float:
    load_env()
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


class Validator(BaseValidatorNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        # pending[forecast_id] = structured forecast response plus resolver state
        self.pending: dict[str, dict] = {}
        self.resolved_count = 0
        self.last_issue_at = 0.0
        # Gate scoring/weight emission to one cadence per forecast horizon.
        self.last_resolution_at = 0.0
        self.last_weights_set_at = 0.0
        self.last_weights_resolved_count = 0
        self.load_masxai_state()
        bt.logging.info("MASXAI MVP validator initialized.")

    # ---------------------------------------------------------------- state
    def load_masxai_state(self):
        if not os.path.exists(C.STATE_FILE):
            return
        try:
            with open(C.STATE_FILE, "r") as f:
                s = json.load(f)
            self.pending = s.get("pending", {})
            self.resolved_count = s.get("resolved_count", 0)
            self.last_issue_at = float(s.get("last_issue_at", 0.0))
            self.last_resolution_at = float(s.get("last_resolution_at", 0.0))
            self.last_weights_set_at = float(s.get("last_weights_set_at", 0.0))
            self.last_weights_resolved_count = int(
                s.get("last_weights_resolved_count", self.resolved_count)
            )
            scores = s.get("scores")
            if scores is not None:
                arr = np.array(scores, dtype=np.float32)
                if arr.shape == self.scores.shape:
                    self.scores = arr
                else:
                    bt.logging.warning(
                        f"Saved scores shape {arr.shape} does not match metagraph shape {self.scores.shape}. "
                        "Performing overlapping copy."
                    )
                    copy_len = min(len(arr), len(self.scores))
                    self.scores[:copy_len] = arr[:copy_len]
            bt.logging.info(
                f"loaded state: {len(self.pending)} pending, "
                f"{self.resolved_count} resolved"
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not load state, starting fresh: {e}")

    def save_masxai_state(self):
        try:
            with open(C.STATE_FILE, "w") as f:
                json.dump(
                    {
                        "pending": self.pending,
                        "resolved_count": self.resolved_count,
                        "last_issue_at": self.last_issue_at,
                        "last_resolution_at": self.last_resolution_at,
                        "last_weights_set_at": self.last_weights_set_at,
                        "last_weights_resolved_count": self.last_weights_resolved_count,
                        "scores": self.scores.tolist(),
                    },
                    f,
                )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not save state: {e}")

    # ------------------------------------------------------------- resolve
    async def resolve_due(self):
        """Resolve every pending forecast whose horizon has passed."""
        now = time.time()
        horizon = float(C.FORECAST_HORIZON_SECONDS)
        if self.last_resolution_at and (now - self.last_resolution_at) < horizon:
            remaining = int(horizon - (now - self.last_resolution_at))
            bt.logging.debug(
                f"resolution interval not reached; next resolution in {remaining}s"
            )
            return

        due = [fid for fid, f in self.pending.items() if f["resolve_at"] <= now]
        if not due:
            return

        # Fetch outcomes concurrently to avoid sequential timeout blocking
        tasks = []
        for fid in due:
            f = self.pending[fid]
            tasks.append(
                oracle.resolve_forecast_outcome(
                    f,
                    subtensor=getattr(self, "subtensor", None),
                )
            )
        
        outcomes = await asyncio.gather(*tasks)

        resolved_this_round = 0
        for fid, outcome in zip(due, outcomes):
            if outcome is None:
                bt.logging.info(f"oracle unavailable for {fid}; deferring resolution")
                continue

            f = self.pending.pop(fid)
            uid = f["uid"]
            prev_score = float(self.scores[uid])
            reward = score_structured_forecast(
                prediction=f.get("prediction"),
                confidence=f.get("confidence"),
                outcome=outcome,
                previous_score=prev_score,
                submitted_at=f.get("submitted_at", f.get("issued_at", 0.0)),
                issued_at=f.get("issued_at", 0.0),
                resolve_at=f.get("resolve_at", 1.0),
            )
            self.scores[uid] = ema_update(float(self.scores[uid]), reward)
            self.resolved_count += 1
            resolved_this_round += 1
            bt.logging.debug(
                f"resolved uid={uid} event={f.get('event_type')} "
                f"prediction={f.get('prediction')} confidence={f.get('confidence')} "
                f"outcome={outcome} "
                f"reward={reward:.3f} -> score={self.scores[uid]:.3f}"
            )
        if resolved_this_round > 0:
            self.last_resolution_at = time.time()
        bt.logging.info(
            f"resolved due forecasts | "
            f"total resolved={self.resolved_count}"
        )

    def should_set_weights(self) -> bool:
        """Set weights at most once per forecast horizon and only after new resolutions."""
        if not super().should_set_weights():
            return False

        now = time.time()
        horizon = float(C.FORECAST_HORIZON_SECONDS)
        if self.last_weights_set_at and (now - self.last_weights_set_at) < horizon:
            remaining = int(horizon - (now - self.last_weights_set_at))
            bt.logging.debug(
                f"weight interval not reached; next set_weights in {remaining}s"
            )
            return False

        if self.resolved_count <= self.last_weights_resolved_count:
            bt.logging.debug(
                "skipping set_weights: no newly resolved forecasts since last weight set"
            )
            return False

        return True

    def set_weights(self):
        """Set weights and persist the horizon gate state only on success."""
        success = super().set_weights()
        if success:
            self.last_weights_set_at = time.time()
            self.last_weights_resolved_count = int(self.resolved_count)
        return success

    # --------------------------------------------------------------- issue
    def build_question(self, event_type: str, reference: dict) -> ForecastSynapse:
        now = time.time()
        resolve_at = now + C.FORECAST_HORIZON_SECONDS
        mins = C.FORECAST_HORIZON_SECONDS // 60
        reference_value = reference.get("reference_value")
        metadata = reference.get("reference_metadata", {})

        if event_type == ForecastEventType.TAO_PRICE_MOVEMENT.value:
            question = (
                f"Will TAO/USD be higher than ${float(reference_value):.4f} "
                f"in {mins} minutes?"
            )
            context = (
                f"Event type: {event_type}\n"
                f"Current TAO/USD reference price: {reference_value}\n"
                f"Forecast window: {C.FORECAST_WINDOW}\n"
                "Use recent Bittensor market, subnet, governance, and ecosystem "
                "signals available to your miner before answering."
            )
        elif event_type == ForecastEventType.NEW_SUBNET_REGISTRATION.value:
            count = int(reference_value)
            question = f"Will at least one new Bittensor subnet register in the next {C.FORECAST_WINDOW}?"
            context = (
                f"Event type: {event_type}\n"
                f"Current subnet count: {count}\n"
                f"Forecast window: {C.FORECAST_WINDOW}"
            )
        else:
            question = f"Will the MASXAI event '{event_type}' occur within {C.FORECAST_WINDOW}?"
            context = f"Event type: {event_type}\nForecast window: {C.FORECAST_WINDOW}"

        return ForecastSynapse(
            forecast_id=uuid.uuid4().hex,
            question=question,
            event_type=event_type,
            asset=C.FORECAST_ASSET,
            reference_value=reference_value,
            reference_metadata=metadata,
            forecast_window=C.FORECAST_WINDOW,
            issued_at=now,
            resolve_at=resolve_at,
            context=context,
        )

    async def issue_round(self):
        """Snapshot price, query all miners, store responses in PENDING."""
        now = time.time()
        interval = max(0.0, _env_float("MASXAI_FORECAST_INTERVAL_SECONDS", C.FORECAST_INTERVAL_SECONDS))
        if self.last_issue_at and now - self.last_issue_at < interval:
            remaining = int(interval - (now - self.last_issue_at))
            bt.logging.debug(f"forecast interval not reached; next issue in {remaining}s")
            return

        event_type = C.ENABLED_EVENT_TYPES[self.resolved_count % len(C.ENABLED_EVENT_TYPES)]
        reference = await oracle.snapshot_reference(
            event_type,
            asset=C.FORECAST_ASSET,
            subtensor=getattr(self, "subtensor", None),
        )
        if reference is None:
            bt.logging.info("oracle unavailable; skipping issue this epoch")
            return

        miner_uids = self.get_miner_uids()
        if len(miner_uids) == 0:
            bt.logging.info("no miners to query this epoch")
            return

        synapse = self.build_question(event_type, reference)
        axons = [self.metagraph.axons[uid] for uid in miner_uids]

        responses = await self.dendrite(
            axons=axons,
            synapse=synapse,
            deserialize=False,
            timeout=C.QUERY_TIMEOUT,
        )

        issued = 0
        answered = 0
        submitted_at = time.time()
        for uid, resp in zip(miner_uids, responses):
            fid = uuid.uuid4().hex
            prediction = resp.prediction
            confidence = resp.confidence
            if prediction is None and resp.probability is not None:
                prediction = resp.probability >= C.NEUTRAL_PROB
                confidence = max(resp.probability, 1.0 - resp.probability)
            if prediction is not None and confidence is not None:
                answered += 1
            self.pending[fid] = {
                "uid": int(uid),
                "forecast_id": resp.forecast_id or fid,
                "event_type": event_type,
                "prediction": prediction,
                "confidence": confidence,
                "probability": resp.probability,  # may be None if no answer
                "reasoning": resp.reasoning,
                "model": resp.model,
                "timestamp": resp.timestamp,
                "submitted_at": _parse_timestamp(resp.timestamp) or submitted_at,
                "reference_value": reference.get("reference_value"),
                "reference_metadata": reference.get("reference_metadata", {}),
                "issued_at": synapse.issued_at,
                "asset": C.FORECAST_ASSET,
                "resolve_at": synapse.resolve_at,
            }
            issued += 1
        bt.logging.info(
            f"issued {issued} {event_type} forecasts @ ref={reference.get('reference_value')} "
            f"| answered={answered}/{len(miner_uids)} "
            f"(resolve in {C.FORECAST_HORIZON_SECONDS//60}m) | "
            f"pending now={len(self.pending)}"
        )
        self.last_issue_at = time.time()

    def get_miner_uids(self) -> list[int]:
        """All registered neurons that are serving an axon (i.e., miners)."""
        uids = []
        for uid in range(self.metagraph.n.item()):
            if self.metagraph.axons[uid].is_serving:
                # skip our own hotkey
                if self.metagraph.hotkeys[uid] != self.wallet.hotkey.ss58_address:
                    uids.append(uid)
        return uids

    # ------------------------------------------------------------- forward
    async def forward(self):
        """One validator step: resolve due → issue new → persist."""
        await self.resolve_due()
        await self.issue_round()
        self.save_masxai_state()
        # brief pause so we don't hot-loop; the base class also paces by epoch
        await asyncio.sleep(5)


def _exit_if_worker_stopped(validator: Validator) -> None:
    thread = getattr(validator, "thread", None)
    if thread is None:
        bt.logging.error(
            "validator worker was not started; exiting for supervisor restart"
        )
        raise SystemExit(1)
    if thread.is_alive():
        return

    err = getattr(validator, "run_exception", None)
    if err is not None:
        bt.logging.error(
            f"validator worker stopped after fatal error; exiting for supervisor restart: {err}"
        )
    else:
        bt.logging.error(
            "validator worker stopped unexpectedly; exiting for supervisor restart"
        )
    raise SystemExit(1)


if __name__ == "__main__":
    with Validator() as validator:
        next_heartbeat_at = 0.0
        while True:
            _exit_if_worker_stopped(validator)
            now = time.time()
            if now >= next_heartbeat_at:
                bt.logging.info(
                    f"MASXAI validator alive | pending={len(validator.pending)} "
                    f"resolved={validator.resolved_count} | "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                next_heartbeat_at = now + 30
            time.sleep(1)
