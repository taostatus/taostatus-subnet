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
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import ForecastSynapse, ForecastEventType
from masxai import constants as C
from masxai import oracle
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.ingest import open_ingest_client_from_env
from masxai.scoring import brier_score, ema_update, score_structured_forecast

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
        # Miner Forecast Ingestion API: optional. ingest_client stays None
        # (every hook below becomes a no-op) unless both INGEST_API_KEY and
        # MASXAI_INGEST_BASE_URL are configured.
        self.ingest_client = open_ingest_client_from_env()
        self.ingest_submit_queue: list[dict[str, Any]] = []
        self.ingest_resolve_queue: list[dict[str, Any]] = []
        self.last_miner_registry_sync_at = 0.0
        self.load_masxai_state()
        bt.logging.info(
            f"MASXAI MVP validator initialized | ingest_enabled={self.ingest_client is not None}"
        )

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
            self.ingest_submit_queue = list(s.get("ingest_submit_queue", []))
            self.ingest_resolve_queue = list(s.get("ingest_resolve_queue", []))
            self.last_miner_registry_sync_at = float(s.get("last_miner_registry_sync_at", 0.0))
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
                        "ingest_submit_queue": self.ingest_submit_queue,
                        "ingest_resolve_queue": self.ingest_resolve_queue,
                        "last_miner_registry_sync_at": self.last_miner_registry_sync_at,
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
            self._queue_ingest_resolution(f, outcome=outcome, reward=reward)
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
                "hotkey": self.metagraph.hotkeys[int(uid)],
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
            self._queue_ingest_submission(fid, self.pending[fid])
            issued += 1
        bt.logging.info(
            f"issued {issued} {event_type} forecasts @ ref={reference.get('reference_value')} "
            f"| answered={answered}/{len(miner_uids)} "
            f"(resolve in {C.FORECAST_HORIZON_SECONDS//60}m) | "
            f"pending now={len(self.pending)}"
        )
        self.last_issue_at = time.time()

    # -------------------------------------------------- forecast ingestion
    @staticmethod
    def _epoch_to_iso(value: Any) -> Optional[str]:
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    def _build_activity_payload(self, forecast: dict) -> dict[str, Any]:
        """Map an internal pending-forecast dict to the ingestion API's CreateActivityDto."""
        event_type = str(forecast.get("event_type") or "")
        if event_type not in {member.value for member in ForecastEventType}:
            event_type = "other"

        probability = forecast.get("probability")
        submitted_at = forecast.get("submitted_at")
        issued_at = forecast.get("issued_at")
        response_time_ms = None
        if isinstance(submitted_at, (int, float)) and isinstance(issued_at, (int, float)):
            response_time_ms = max(0, int((float(submitted_at) - float(issued_at)) * 1000))

        payload: dict[str, Any] = {
            "eventType": event_type,
            "questionKey": forecast.get("question_key") or forecast.get("forecast_id"),
            "forecastId": forecast.get("forecast_id"),
            "resolveAt": self._epoch_to_iso(forecast.get("resolve_at")),
            "prediction": forecast.get("prediction"),
            "probability": probability,
            "confidence": forecast.get("confidence"),
            "reasoning": forecast.get("reasoning") or None,
            "model": forecast.get("model") or None,
            "isNoAnswer": probability is None,
            "responseTimeMs": response_time_ms,
            "submittedAt": self._epoch_to_iso(submitted_at),
        }
        return {key: value for key, value in payload.items() if value is not None}

    def _queue_ingest_submission(self, fid: str, forecast: dict) -> None:
        """Queue one forecast activity for POSTing to the ingestion API. No-op if unconfigured."""
        if self.ingest_client is None:
            return
        hotkey = forecast.get("hotkey")
        if not hotkey:
            return
        self._enqueue_bounded(
            self.ingest_submit_queue,
            {"fid": fid, "hotkey": hotkey, "payload": self._build_activity_payload(forecast)},
        )

    def _queue_ingest_resolution(self, forecast: dict, *, outcome: bool, reward: float) -> None:
        """Queue one resolution PATCH. Skipped if the submission never got an activity id."""
        if self.ingest_client is None:
            return
        activity_id = forecast.get("ingest_activity_id")
        hotkey = forecast.get("hotkey")
        if not activity_id or not hotkey:
            return
        probability = forecast.get("probability")
        payload: dict[str, Any] = {"outcome": bool(outcome), "rewardComposite": float(reward)}
        if probability is not None:
            payload["brierScore"] = brier_score(probability, outcome)
        self._enqueue_bounded(
            self.ingest_resolve_queue,
            {"hotkey": hotkey, "activity_id": activity_id, "payload": payload},
        )

    @staticmethod
    def _enqueue_bounded(queue: list[dict[str, Any]], item: dict[str, Any]) -> None:
        """Append to an ingest queue, dropping the oldest entry once it hits the configured cap."""
        max_len = max(0, int(_env_float(C.INGEST_QUEUE_MAX_ENV, C.INGEST_QUEUE_MAX)))
        queue.append(item)
        if max_len and len(queue) > max_len:
            del queue[: len(queue) - max_len]

    @staticmethod
    def _is_ingest_client_error(exc: Exception) -> bool:
        """True for a non-retryable 4xx - the caller should drop, not requeue."""
        if not isinstance(exc, httpx.HTTPStatusError):
            return False
        status = exc.response.status_code if exc.response is not None else None
        return status is not None and 400 <= status < 500

    async def flush_ingest_submissions(self):
        """Best-effort retrying sender for ingestion-API activity POSTs."""
        if not self.ingest_submit_queue or self.ingest_client is None:
            return
        remaining = []
        for item in self.ingest_submit_queue:
            fid = item.get("fid")
            hotkey = item.get("hotkey")
            payload = item.get("payload") or {}
            try:
                result = await self.ingest_client.submit_activity(hotkey, payload)
                activity_id = result.get("id") if isinstance(result, dict) else None
                if activity_id and fid in self.pending:
                    self.pending[fid]["ingest_activity_id"] = activity_id
            except Exception as e:  # noqa: BLE001
                if self._is_ingest_client_error(e):
                    bt.logging.warning(
                        f"ingest activity submit rejected, dropping: hotkey={hotkey}: {e}"
                    )
                    continue
                bt.logging.warning(f"ingest activity submit failed, will retry: {e}")
                remaining.append(item)
        self.ingest_submit_queue = remaining

    async def flush_ingest_resolutions(self):
        """Best-effort retrying sender for ingestion-API resolve PATCHes."""
        if not self.ingest_resolve_queue or self.ingest_client is None:
            return
        remaining = []
        for item in self.ingest_resolve_queue:
            hotkey = item.get("hotkey")
            activity_id = item.get("activity_id")
            payload = item.get("payload") or {}
            try:
                await self.ingest_client.resolve_activity(hotkey, activity_id, payload)
            except Exception as e:  # noqa: BLE001
                if self._is_ingest_client_error(e):
                    bt.logging.warning(
                        f"ingest activity resolve rejected, dropping: "
                        f"hotkey={hotkey} activity_id={activity_id}: {e}"
                    )
                    continue
                bt.logging.warning(f"ingest activity resolve failed, will retry: {e}")
                remaining.append(item)
        self.ingest_resolve_queue = remaining

    def _build_miner_registry_payload(self, uid: int) -> dict[str, Any]:
        metagraph = self.metagraph
        payload: dict[str, Any] = {
            "uid": int(uid),
            "hotkey": metagraph.hotkeys[uid],
            "netuid": int(getattr(self.config, "netuid", 0)),
        }
        coldkeys = getattr(metagraph, "coldkeys", None)
        if coldkeys is not None and uid < len(coldkeys):
            payload["coldkey"] = coldkeys[uid]
        stake = getattr(metagraph, "stake", None)
        if stake is not None and uid < len(stake):
            payload["stakeTao"] = float(stake[uid])
        # metagraph.trust isn't present on every bittensor version's metagraph -
        # read defensively and omit rather than assume it exists.
        trust = getattr(metagraph, "trust", None)
        if trust is not None and uid < len(trust):
            payload["trust"] = float(trust[uid])
        incentive = getattr(metagraph, "incentive", None)
        if incentive is not None and uid < len(incentive):
            payload["incentive"] = float(incentive[uid])
        active = getattr(metagraph, "active", None)
        if active is not None and uid < len(active):
            payload["active"] = bool(active[uid])
        return payload

    async def sync_miner_registry(self):
        """Periodically upsert metagraph miner state to the ingestion API."""
        if self.ingest_client is None:
            return
        interval = _env_float(
            C.INGEST_MINER_SYNC_INTERVAL_SECONDS_ENV,
            C.INGEST_MINER_SYNC_INTERVAL_SECONDS,
        )
        now = time.time()
        if self.last_miner_registry_sync_at and now - self.last_miner_registry_sync_at < interval:
            return

        hotkeys = getattr(self.metagraph, "hotkeys", [])
        synced = 0
        for uid in range(len(hotkeys)):
            try:
                payload = self._build_miner_registry_payload(uid)
                await self.ingest_client.upsert_miner(payload)
                synced += 1
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"miner registry sync failed for uid={uid}: {e}")
        self.last_miner_registry_sync_at = now
        bt.logging.info(f"synced {synced}/{len(hotkeys)} miner(s) to ingestion API")

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
        await self.flush_ingest_submissions()
        await self.flush_ingest_resolutions()
        await self.sync_miner_registry()
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
