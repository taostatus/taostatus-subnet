"""
neurons/validator.py - MASXAI MVP validator.

The validator issues structured forecasting tasks, stores miner forecasts, waits
for the forecast window to complete, resolves ground truth through objective
oracles, scores miners, and lets the template weight machinery use self.scores.
"""

import asyncio
import hashlib
import json
import os
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import ForecastSynapse, ForecastEventType
from masxai import constants as C
from masxai import oracle
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.oracle_bt import (
    BtForecastQuestion,
    BtForecastResolution,
    bt_forecast_required_from_env,
    bt_forecast_run_id_from_env,
    open_bt_forecast_client_from_env,
    parse_api_timestamp,
)
from masxai.scoring import brier_score, ema_update, score_structured_forecast

try:
    from template.base.validator import BaseValidatorNeuron
except Exception:
    class BaseValidatorNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseValidatorNeuron requires a working bittensor install")

        def should_set_weights(self) -> bool:
            return False

        def set_weights(self):
            return None


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


def _env_int(name: str, default: int) -> int:
    load_env()
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _env_flag(name: str, default: bool = False) -> bool:
    load_env()
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _state_file_path() -> Path:
    load_env()
    configured = os.getenv(C.VALIDATOR_STATE_FILE_ENV, "").strip()
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_absolute() else Path.cwd() / path

    path = Path(C.STATE_FILE).expanduser()
    return path if path.is_absolute() else _repo_root() / path


class Validator(BaseValidatorNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        # pending[key] = structured forecast response plus resolver state.
        # Central BT-Forecast keys are deterministic by run/question/miner.
        self.pending: dict[str, dict] = {}
        self.issued_questions: dict[str, float] = {}
        self.feedback_queue: list[dict[str, Any]] = []
        self.bt_forecast_runs: dict[str, dict[str, Any]] = {}
        self.bt_forecast_client = open_bt_forecast_client_from_env()
        self.bt_forecast_required = bt_forecast_required_from_env()
        self.resolved_count = 0
        self.last_issue_at = 0.0
        # Gate scoring/weight emission to one cadence per forecast horizon.
        self.last_resolution_at = 0.0
        self.last_weights_set_at = 0.0
        self.last_weights_resolved_count = 0
        self.load_masxai_state()
        bt.logging.info(
            "MASXAI validator initialized | "
            f"bt_forecast_enabled={self.bt_forecast_client is not None} "
            f"bt_forecast_required={self.bt_forecast_required} "
            f"state_file={_state_file_path()}"
        )

    # ---------------------------------------------------------------- state
    def load_masxai_state(self):
        if not hasattr(self, "issued_questions"):
            self.issued_questions = {}
        if not hasattr(self, "feedback_queue"):
            self.feedback_queue = []
        if not hasattr(self, "bt_forecast_runs"):
            self.bt_forecast_runs = {}
        state_path = _state_file_path()
        if not state_path.exists():
            bt.logging.info(f"validator state file not found: {state_path}")
            return
        try:
            with state_path.open("r") as f:
                s = json.load(f)
            self.pending = s.get("pending", {})
            sanitized = self._sanitize_fallback_pending()
            self.issued_questions = {
                str(k): float(v) for k, v in s.get("issued_questions", {}).items()
            }
            self.feedback_queue = list(s.get("feedback_queue", []))
            self.bt_forecast_runs = {
                str(k): v
                for k, v in s.get("bt_forecast_runs", {}).items()
                if isinstance(v, dict)
            }
            self.resolved_count = s.get("resolved_count", 0)
            self.last_issue_at = float(s.get("last_issue_at", 0.0))
            pruned = self.prune_masxai_state()
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
                f"loaded state from {state_path}: {len(self.pending)} pending, "
                f"{self.resolved_count} resolved, "
                f"{len(self.feedback_queue)} feedback payload(s) queued"
            )
            if sanitized:
                bt.logging.info(
                    f"normalized {sanitized} fallback forecast(s) to no-answer"
                )
            if any(pruned.values()):
                bt.logging.info(f"pruned validator state on load: {pruned}")
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not load state, starting fresh: {e}")

    def _sanitize_fallback_pending(self) -> int:
        sanitized = 0
        for forecast in self.pending.values():
            if not self._is_no_answer_model(forecast.get("model")):
                continue
            if (
                forecast.get("probability") is not None
                or forecast.get("prediction") is not None
                or forecast.get("confidence") is not None
            ):
                sanitized += 1
            forecast["probability"] = None
            forecast["prediction"] = None
            forecast["confidence"] = None
        return sanitized

    def save_masxai_state(self):
        try:
            pruned = self.prune_masxai_state()
            if any(pruned.values()):
                bt.logging.info(f"pruned validator state before save: {pruned}")
            state_path = _state_file_path()
            state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = state_path.with_name(f"{state_path.name}.tmp")
            with tmp_path.open("w") as f:
                json.dump(
                    {
                        "pending": self.pending,
                        "issued_questions": self.issued_questions,
                        "feedback_queue": self.feedback_queue,
                        "bt_forecast_runs": self.bt_forecast_runs,
                        "resolved_count": self.resolved_count,
                        "last_issue_at": self.last_issue_at,
                        "last_resolution_at": self.last_resolution_at,
                        "last_weights_set_at": self.last_weights_set_at,
                        "last_weights_resolved_count": self.last_weights_resolved_count,
                        "scores": self.scores.tolist(),
                    },
                    f,
                )
            os.replace(tmp_path, state_path)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"could not save state: {e}")

    def prune_masxai_state(self, *, now: Optional[float] = None) -> dict[str, int]:
        """Keep persisted validator state bounded and safe to read after restarts."""
        now = time.time() if now is None else now
        stats = {
            "malformed_pending": 0,
            "stale_pending": 0,
            "old_runs": 0,
            "feedback": 0,
        }

        resolution_wait = _env_float(
            C.BT_FORECAST_RESOLUTION_WAIT_SECONDS_ENV,
            C.BT_FORECAST_RESOLUTION_WAIT_SECONDS,
        )
        for fid, forecast in list(getattr(self, "pending", {}).items()):
            if not isinstance(forecast, dict):
                self.pending.pop(fid, None)
                stats["malformed_pending"] += 1
                continue
            try:
                resolve_at = float(forecast.get("resolve_at") or 0.0)
            except (TypeError, ValueError):
                self.pending.pop(fid, None)
                stats["malformed_pending"] += 1
                continue
            if resolve_at <= 0.0:
                self.pending.pop(fid, None)
                stats["malformed_pending"] += 1
                continue
            if (
                forecast.get("source") == "bt_forecast"
                and now - resolve_at > resolution_wait
            ):
                self.pending.pop(fid, None)
                stats["stale_pending"] += 1

        max_feedback = max(
            0,
            _env_int(
                C.BT_FORECAST_FEEDBACK_QUEUE_MAX_ENV,
                C.BT_FORECAST_FEEDBACK_QUEUE_MAX,
            ),
        )
        if max_feedback and len(getattr(self, "feedback_queue", [])) > max_feedback:
            overflow = len(self.feedback_queue) - max_feedback
            self.feedback_queue = self.feedback_queue[-max_feedback:]
            stats["feedback"] = overflow

        retention_seconds = max(
            0.0,
            _env_float(
                C.BT_FORECAST_RUN_STATE_RETENTION_SECONDS_ENV,
                C.BT_FORECAST_RUN_STATE_RETENTION_SECONDS,
            ),
        )
        pending_runs = {
            str(forecast.get("run_id"))
            for forecast in getattr(self, "pending", {}).values()
            if isinstance(forecast, dict) and forecast.get("source") == "bt_forecast"
        }
        for run_id, run_state in list(getattr(self, "bt_forecast_runs", {}).items()):
            if run_id in pending_runs:
                continue
            if not isinstance(run_state, dict):
                self.bt_forecast_runs.pop(run_id, None)
                stats["old_runs"] += 1
                continue
            last_seen = self._bt_run_last_seen_timestamp(str(run_id), run_state)
            if (
                retention_seconds > 0.0
                and last_seen is not None
                and now - last_seen > retention_seconds
            ):
                self.bt_forecast_runs.pop(run_id, None)
                stats["old_runs"] += 1
        return stats

    # ------------------------------------------------------------- weights
    def _has_scored_weights(self) -> bool:
        """True only after real resolutions have produced positive miner scores."""
        resolved_count = int(getattr(self, "resolved_count", 0) or 0)
        if resolved_count < self._min_resolved_before_weights():
            return False

        scores = getattr(self, "scores", None)
        if scores is None:
            return False
        score_array = np.nan_to_num(
            np.asarray(scores, dtype=np.float32),
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )
        positive_scores = int(np.count_nonzero(score_array > 0.0))
        return positive_scores >= self._min_allowed_weight_count()

    def _min_resolved_before_weights(self) -> int:
        return max(
            1,
            _env_int(
                C.MIN_RESOLVED_BEFORE_WEIGHTS_ENV,
                C.MIN_RESOLVED_BEFORE_WEIGHTS,
            ),
        )

    def _min_allowed_weight_count(self) -> int:
        try:
            return max(
                1,
                int(self.subtensor.min_allowed_weights(netuid=self.config.netuid)),
            )
        except Exception:
            return 1

    def should_set_weights(self) -> bool:
        if not self._has_scored_weights():
            bt.logging.debug(
                "skipping set_weights: waiting for resolved, scored miner forecasts "
                f"(resolved={int(getattr(self, 'resolved_count', 0) or 0)}, "
                f"required={self._min_resolved_before_weights()})"
            )
            return False
        return super().should_set_weights()

    def set_weights(self):
        if not self._has_scored_weights():
            bt.logging.warning(
                "refusing to set validator weights before any miner has a "
                "positive score from a resolved forecast"
            )
            return None
        return super().set_weights()

    # ------------------------------------------------------------- resolve
    async def resolve_due(self):
        """Resolve every pending forecast whose horizon has passed."""
        now = time.time()
        due = []
        malformed = []
        for fid, forecast in list(self.pending.items()):
            try:
                resolve_at = float(forecast.get("resolve_at") or 0.0)
            except (AttributeError, TypeError, ValueError):
                malformed.append(fid)
                continue
            if resolve_at <= 0.0:
                malformed.append(fid)
                continue
            if resolve_at <= now:
                due.append(fid)
        if malformed:
            self._drop_pending(malformed)
            bt.logging.warning(
                f"dropped {len(malformed)} malformed pending forecast(s) before resolution"
            )
        if not due:
            await self.flush_bt_feedback()
            return

        self._log_resolution_due(due, now=now)

        bt_due = [fid for fid in due if self.pending[fid].get("source") == "bt_forecast"]
        bt_due_set = set(bt_due)
        local_due = [fid for fid in due if fid not in bt_due_set]

        if bt_due:
            await self.resolve_bt_forecast_due(bt_due, now=now)
        if local_due:
            await self.resolve_local_due(local_due)
        await self.flush_bt_feedback()

    async def resolve_local_due(self, due: list[str]):
        """Resolve legacy local-oracle forecasts."""
        tasks = []
        valid_due = []
        for fid in due:
            if fid not in self.pending:
                continue
            f = self.pending[fid]
            valid_due.append(fid)
            tasks.append(
                oracle.resolve_forecast_outcome(
                    f,
                    subtensor=getattr(self, "subtensor", None),
                )
            )

        if not tasks:
            return

        outcomes = await asyncio.gather(*tasks)

        resolved_this_round = 0
        for fid, outcome in zip(valid_due, outcomes):
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
                probability=f.get("probability"),
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

    async def resolve_bt_forecast_due(self, due: list[str], *, now: float):
        """Resolve centralized BT-Forecast questions through the FastAPI API."""
        client = self._bt_forecast_client()
        if client is None:
            bt.logging.warning("BT-Forecast API unavailable; deferring centralized resolutions")
            return

        by_run: dict[str, list[str]] = defaultdict(list)
        for fid in due:
            f = self.pending.get(fid)
            if not f:
                continue
            by_run[str(f.get("run_id") or bt_forecast_run_id_from_env())].append(fid)

        fetch_plan: list[tuple[str, list[str]]] = []
        skipped_runs = 0
        for run_id, fids in by_run.items():
            run_state = self._bt_run_state(run_id)
            next_poll_at = self._bt_next_resolution_poll_at(run_state)
            if next_poll_at is not None and next_poll_at > now:
                skipped_runs += 1
                remaining = int(next_poll_at - now)
                bt.logging.debug(
                    f"BT-Forecast run {run_id} resolution retry not due for {remaining}s"
                )
                continue
            fetch_plan.append((run_id, fids))

        if not fetch_plan:
            if skipped_runs:
                bt.logging.debug(
                    f"BT-Forecast resolution pass deferred by retry schedule | "
                    f"runs_waiting={skipped_runs}"
                )
            return

        resolution_wait = _env_float(
            C.BT_FORECAST_RESOLUTION_WAIT_SECONDS_ENV,
            C.BT_FORECAST_RESOLUTION_WAIT_SECONDS,
        )
        resolved_questions = 0
        dropped_questions = 0
        unresolved_questions = 0
        stale_forecasts = 0
        runs_polled = 0

        fetches = [
            client.get_resolutions(run_id=run_id)
            for run_id, _fids in fetch_plan
        ]
        fetch_results = await asyncio.gather(*fetches, return_exceptions=True)

        for (run_id, fids), fetch_result in zip(fetch_plan, fetch_results):
            run_state = self._bt_run_state(run_id)
            polled_at = datetime.now(timezone.utc).isoformat()
            runs_polled += 1
            run_state["last_resolution_polled_at"] = polled_at

            if isinstance(fetch_result, Exception):
                run_state["last_resolution_error_at"] = polled_at
                self._schedule_next_bt_resolution_poll(run_state, now=now)
                bt.logging.warning(
                    f"BT-Forecast resolutions fetch failed run_id={run_id}: "
                    f"{fetch_result}"
                )
                continue
            resolutions = list(fetch_result or [])
            run_state["last_resolution_count"] = len(resolutions)

            resolution_by_key = {r.question_key: r for r in resolutions}
            by_question: dict[str, list[str]] = defaultdict(list)
            for fid in fids:
                f = self.pending.get(fid)
                if f:
                    by_question[str(f.get("question_key") or fid)].append(fid)

            run_unresolved_questions = 0
            for question_key, question_fids in by_question.items():
                sample = self.pending.get(question_fids[0])
                if not sample:
                    continue
                resolution = resolution_by_key.get(question_key)
                try:
                    sample_resolve_at = float(sample.get("resolve_at", now))
                except (TypeError, ValueError):
                    sample_resolve_at = now
                status = str(getattr(resolution, "status", "") or "").strip().lower()
                if resolution is None or status in C.BT_FORECAST_OPEN_STATUSES:
                    if now - sample_resolve_at > resolution_wait:
                        self._drop_pending(question_fids)
                        dropped_questions += 1
                        bt.logging.info(
                            f"dropped unscored BT-Forecast question after wait window: {question_key}"
                        )
                    else:
                        unresolved_questions += 1
                        run_unresolved_questions += 1
                    continue

                if status in C.BT_FORECAST_UNSCORED_TERMINAL_STATUSES:
                    self._drop_pending(question_fids)
                    dropped_questions += 1
                    bt.logging.info(
                        f"dropped unscored BT-Forecast question status={status}: "
                        f"{question_key}"
                    )
                    continue

                outcome = resolution.bool_outcome()
                if outcome is None:
                    unresolved_questions += 1
                    run_unresolved_questions += 1
                    bt.logging.warning(
                        f"BT-Forecast resolution has no boolean outcome "
                        f"status={status or 'unknown'} question_key={question_key}"
                    )
                    continue

                forecasts = [self.pending[fid] for fid in question_fids if fid in self.pending]
                feedback_payload = self._build_miner_results_payload(
                    run_id=run_id,
                    question_key=question_key,
                    forecasts=forecasts,
                    resolution=resolution,
                    outcome=outcome,
                )
                for fid in question_fids:
                    if fid not in self.pending:
                        continue
                    f = self.pending.pop(fid)
                    uid = self._forecast_uid(f)
                    if uid is None or not self._scoreable_uid(uid, f):
                        stale_forecasts += 1
                        continue
                    prev_score = float(self.scores[uid])
                    reward = self._score_resolved_forecast(f, outcome)
                    self.scores[uid] = ema_update(float(self.scores[uid]), reward)
                    self.resolved_count += 1
                    bt.logging.debug(
                        f"resolved bt uid={uid} family={f.get('family')} "
                        f"probability={f.get('probability')} outcome={outcome} "
                        f"reward={reward:.3f} prev={prev_score:.3f} "
                        f"score={self.scores[uid]:.3f}"
                    )

                if feedback_payload["results"]:
                    self.feedback_queue.append(feedback_payload)
                resolved_questions += 1

            if run_unresolved_questions:
                self._schedule_next_bt_resolution_poll(run_state, now=now)
            else:
                run_state.pop("next_resolution_poll_at", None)

        bt.logging.info(
            f"BT-Forecast resolution pass | runs_polled={runs_polled} "
            f"runs_waiting={skipped_runs} questions_resolved={resolved_questions} "
            f"questions_unresolved={unresolved_questions} "
            f"questions_dropped={dropped_questions} stale_forecasts={stale_forecasts} "
            f"total_resolved={self.resolved_count}"
        )

    def _log_resolution_due(self, due: list[str], *, now: float) -> None:
        last_logged = float(getattr(self, "_last_resolution_due_log_at", 0.0) or 0.0)
        if now - last_logged < 60.0:
            return
        self._last_resolution_due_log_at = now
        bt_due = 0
        runs = set()
        questions = set()
        oldest_resolve_at = now
        for fid in due:
            forecast = self.pending.get(fid)
            if not forecast:
                continue
            try:
                resolve_at = float(forecast.get("resolve_at") or now)
            except (TypeError, ValueError):
                resolve_at = now
            oldest_resolve_at = min(oldest_resolve_at, resolve_at)
            if forecast.get("source") == "bt_forecast":
                bt_due += 1
                runs.add(str(forecast.get("run_id") or "unknown"))
                questions.add(str(forecast.get("question_key") or fid))
        bt.logging.info(
            f"resolution due | total={len(due)} bt={bt_due} "
            f"local={len(due) - bt_due} bt_runs={len(runs)} "
            f"bt_questions={len(questions)} oldest_lag_s={int(max(0.0, now - oldest_resolve_at))}"
        )

    def _bt_resolution_retry_seconds(self) -> float:
        return max(
            0.0,
            _env_float(
                C.BT_FORECAST_RESOLUTION_RETRY_SECONDS_ENV,
                C.BT_FORECAST_RESOLUTION_RETRY_SECONDS,
            ),
        )

    @staticmethod
    def _bt_next_resolution_poll_at(run_state: dict[str, Any]) -> Optional[float]:
        try:
            next_poll_at = run_state.get("next_resolution_poll_at")
            if next_poll_at is None:
                return None
            return float(next_poll_at)
        except (TypeError, ValueError):
            return None

    def _schedule_next_bt_resolution_poll(
        self,
        run_state: dict[str, Any],
        *,
        now: float,
    ) -> None:
        retry_seconds = self._bt_resolution_retry_seconds()
        if retry_seconds <= 0.0:
            run_state.pop("next_resolution_poll_at", None)
            return
        run_state["next_resolution_poll_at"] = now + retry_seconds

    @staticmethod
    def _forecast_uid(forecast: dict) -> Optional[int]:
        try:
            return int(forecast["uid"])
        except (KeyError, TypeError, ValueError):
            return None

    def _scoreable_uid(self, uid: int, forecast: dict) -> bool:
        scores = getattr(self, "scores", None)
        if scores is None or uid < 0 or uid >= len(scores):
            bt.logging.warning(
                f"dropping resolved forecast for unscoreable uid={uid}: "
                "uid is outside the current score array"
            )
            return False

        try:
            metagraph_size = self._metagraph_size()
        except Exception:
            metagraph_size = len(scores)
        if metagraph_size > 0 and uid >= metagraph_size:
            bt.logging.warning(
                f"dropping resolved forecast for stale uid={uid}: "
                "uid is outside the current metagraph"
            )
            return False

        hotkey = forecast.get("hotkey")
        hotkeys = getattr(getattr(self, "metagraph", None), "hotkeys", [])
        if hotkey and uid < len(hotkeys) and hotkeys[uid] != hotkey:
            bt.logging.warning(
                f"dropping resolved forecast for stale uid={uid}: "
                "hotkey changed since forecast submission"
            )
            return False
        return True

    def _score_resolved_forecast(self, forecast: dict, outcome: bool) -> float:
        uid = int(forecast["uid"])
        return score_structured_forecast(
            prediction=forecast.get("prediction"),
            confidence=forecast.get("confidence"),
            probability=forecast.get("probability"),
            outcome=outcome,
            previous_score=float(self.scores[uid]),
            submitted_at=forecast.get("submitted_at", forecast.get("issued_at", 0.0)),
            issued_at=forecast.get("issued_at", 0.0),
            resolve_at=forecast.get("resolve_at", 1.0),
        )

    def _drop_pending(self, fids: list[str]) -> None:
        for fid in fids:
            self.pending.pop(fid, None)

    async def flush_bt_feedback(self):
        """Best-effort retrying sender for validator -> BT-Forecast calibration feedback."""
        if not getattr(self, "feedback_queue", None):
            return
        client = self._bt_forecast_client()
        if client is None:
            return
        remaining = []
        for payload in self.feedback_queue:
            try:
                await client.post_miner_results(payload)
                bt.logging.info(
                    f"posted BT-Forecast miner feedback question_key={payload.get('question_key')} "
                    f"results={len(payload.get('results', []))}"
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(
                    f"BT-Forecast miner feedback post failed "
                    f"question_key={payload.get('question_key')}: {e}"
                )
                remaining.append(payload)
        self.feedback_queue = remaining

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
        """Fetch/issue forecast questions, query miners, and store responses."""
        now = time.time()

        client = self._bt_forecast_client()
        if client is not None:
            current_run_id = bt_forecast_run_id_from_env()
            await self.issue_bt_forecast_round(
                client=client,
                now=now,
                run_id=current_run_id,
            )
            await self.retry_unanswered_bt_forecast_runs(
                client=client,
                now=now,
                exclude_run_id=current_run_id,
            )
            return

        if not self._issue_interval_reached(now):
            return

        if self._bt_forecast_required():
            bt.logging.warning(
                "MASXAI_BT_FORECAST_REQUIRED=true but BT_FORECAST_BEARER_TOKEN is unset; "
                "skipping legacy local issue"
            )
            self.last_issue_at = time.time()
            return

        await self.issue_local_round(now=now)
        self.last_issue_at = time.time()

    def _issue_interval_reached(self, now: float) -> bool:
        interval = max(
            0.0,
            _env_float("MASXAI_FORECAST_INTERVAL_SECONDS", C.FORECAST_INTERVAL_SECONDS),
        )
        if self.last_issue_at and now - self.last_issue_at < interval:
            remaining = int(interval - (now - self.last_issue_at))
            bt.logging.debug(f"forecast interval not reached; next issue in {remaining}s")
            return False
        return True

    async def issue_local_round(self, *, now: float):
        """Legacy local-oracle issue path for development and fallback."""
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
        response_list = list(responses or [])
        for index, uid in enumerate(miner_uids):
            resp = response_list[index] if index < len(response_list) else None
            fid = uuid.uuid4().hex
            probability, prediction, confidence = self._normalize_miner_response(resp)
            if probability is not None:
                answered += 1
            self.pending[fid] = {
                "uid": int(uid),
                "forecast_id": getattr(resp, "forecast_id", "") or fid,
                "event_type": event_type,
                "prediction": prediction,
                "confidence": confidence,
                "probability": probability,
                "reasoning": getattr(resp, "reasoning", ""),
                "model": getattr(resp, "model", "") or "no-response",
                "timestamp": getattr(resp, "timestamp", ""),
                "submitted_at": _parse_timestamp(getattr(resp, "timestamp", "")) or submitted_at,
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

    async def issue_bt_forecast_round(
        self,
        *,
        client,
        now: float,
        run_id: Optional[str] = None,
    ):
        """Poll the daily BT-Forecast run, then relay questions once complete."""
        run_id = run_id or bt_forecast_run_id_from_env()
        run_state = self._bt_run_state(run_id)
        if run_state.get("questions_issued_at"):
            retry_unanswered = self._bt_unanswered_retry_due(run_id, run_state, now)
            if not retry_unanswered:
                if self._bt_run_has_unanswered_pending(run_id, now=now):
                    bt.logging.debug(
                        f"BT-Forecast run {run_id} waiting before retrying "
                        "unanswered miner forecasts"
                    )
                else:
                    bt.logging.debug(f"BT-Forecast run {run_id} already issued")
                return
            bt.logging.info(
                f"BT-Forecast run {run_id} has unanswered miner forecasts; "
                "retrying unanswered entries"
            )
        else:
            retry_unanswered = False

        next_poll_at = float(run_state.get("next_poll_at") or 0.0)
        if next_poll_at > now:
            remaining = int(next_poll_at - now)
            bt.logging.debug(
                f"BT-Forecast run {run_id} waiting for next status poll in {remaining}s"
            )
            return

        try:
            run = await client.get_run(run_id)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"BT-Forecast run poll failed run_id={run_id}: {e}")
            run_state["next_poll_at"] = now + C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
            return

        run_state.update(
            {
                "run_id": run.run_id,
                "status": run.status,
                "generation": run.generation,
                "question_count": run.question_count,
                "ready_at": run.ready_at,
                "template_version": run.template_version,
                "measurement_version": run.measurement_version,
                "poll_after_s": run.poll_after_s,
                "last_polled_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        if not self._bt_run_generation_complete(run.generation):
            poll_after_s = self._bt_run_poll_after_seconds(run.poll_after_s)
            run_state["poll_after_s"] = poll_after_s
            run_state["next_poll_at"] = now + poll_after_s
            bt.logging.info(
                f"BT-Forecast run {run_id} generation={run.generation or 'unknown'} "
                f"status={run.status}; polling again in {poll_after_s}s"
            )
            return

        include_lineage = _env_flag(C.BT_FORECAST_INCLUDE_LINEAGE_ENV, False)
        questions = self._bt_cached_questions(run_state)
        if questions is None:
            try:
                questions = await client.get_questions(run_id, include_lineage=include_lineage)
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"BT-Forecast question fetch failed run_id={run_id}: {e}")
                run_state["next_poll_at"] = now + C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
                return
            run_state["questions_fetched_at"] = datetime.now(timezone.utc).isoformat()
            run_state["questions"] = [self._bt_serialize_question(q) for q in questions]

        run_state["question_keys"] = [q.question_key for q in questions]
        run_state["next_poll_at"] = None

        questions = [q for q in questions if not q.predetermined_at_creation]
        if retry_unanswered:
            questions = [
                q
                for q in questions
                if self._bt_question_has_unanswered_pending(
                    run_id,
                    q.question_key,
                    now=now,
                )
            ]
        else:
            questions = [q for q in questions if self._should_issue_bt_question(q, now=now)]
        max_questions = _env_int(
            C.BT_FORECAST_MAX_QUESTIONS_ENV,
            C.BT_FORECAST_MAX_QUESTIONS_PER_ROUND,
        )
        if max_questions > 0:
            questions = questions[:max_questions]
        if not questions:
            if retry_unanswered:
                run_state["last_unanswered_retry_at"] = datetime.now(timezone.utc).isoformat()
                bt.logging.info(
                    f"BT-Forecast run {run_id}: no unanswered open miner forecasts to retry"
                )
            else:
                bt.logging.info(f"BT-Forecast run {run_id}: no new miner-safe questions to issue")
                run_state["questions_issued_at"] = datetime.now(timezone.utc).isoformat()
                run_state["issued_question_count"] = 0
            return

        miner_uids = self.get_miner_uids()
        if len(miner_uids) == 0:
            bt.logging.info("no miners to query this epoch")
            return

        issued = 0
        answered = 0
        for question in questions:
            question_miner_uids = miner_uids
            if retry_unanswered:
                question_miner_uids = self._bt_unanswered_uids_for_question(
                    run_id,
                    question.question_key,
                    miner_uids,
                    now=now,
                )
                if not question_miner_uids:
                    continue
            synapse = self.build_bt_forecast_synapse(question, run_id=run_id)
            axons = [self.metagraph.axons[uid] for uid in question_miner_uids]
            responses = await self.dendrite(
                axons=axons,
                synapse=synapse,
                deserialize=False,
                timeout=C.QUERY_TIMEOUT,
            )
            count, answered_count = self._store_bt_forecast_responses(
                run_id=run_id,
                question=question,
                synapse=synapse,
                miner_uids=question_miner_uids,
                responses=responses,
            )
            issued += count
            answered += answered_count
            if answered_count > 0:
                self.issued_questions[question.question_key] = now

        if not run_state.get("questions_issued_at"):
            run_state["questions_issued_at"] = datetime.now(timezone.utc).isoformat()
        if retry_unanswered:
            run_state["last_unanswered_retry_at"] = datetime.now(timezone.utc).isoformat()
        run_state["issued_question_count"] = len(questions)
        run_state["last_issue_call_count"] = issued
        run_state["last_issue_answered_count"] = answered
        self.last_issue_at = time.time()
        bt.logging.info(
            f"issued {issued} BT-Forecast miner calls from run={run_id} "
            f"questions={len(questions)} answered={answered}/{issued} "
            f"pending now={len(self.pending)}"
        )

    async def retry_unanswered_bt_forecast_runs(
        self,
        *,
        client,
        now: float,
        exclude_run_id: Optional[str] = None,
    ) -> None:
        """Retry unanswered forecasts from earlier still-open BT-Forecast runs."""
        for run_id, run_state in list(getattr(self, "bt_forecast_runs", {}).items()):
            if run_id == exclude_run_id or not isinstance(run_state, dict):
                continue
            if not run_state.get("questions_issued_at"):
                continue
            if not self._bt_unanswered_retry_due(run_id, run_state, now):
                continue
            await self.issue_bt_forecast_round(
                client=client,
                now=now,
                run_id=run_id,
            )

    def _bt_run_state(self, run_id: str) -> dict[str, Any]:
        if not hasattr(self, "bt_forecast_runs"):
            self.bt_forecast_runs = {}
        state = self.bt_forecast_runs.get(run_id)
        if not isinstance(state, dict):
            state = {}
            self.bt_forecast_runs[run_id] = state
        return state

    @staticmethod
    def _bt_run_last_seen_timestamp(
        run_id: str,
        run_state: dict[str, Any],
    ) -> Optional[float]:
        timestamps = []
        for key in (
            "last_unanswered_retry_at",
            "questions_issued_at",
            "questions_fetched_at",
            "last_polled_at",
        ):
            parsed = _parse_timestamp(str(run_state.get(key) or ""))
            if parsed is not None:
                timestamps.append(parsed)
        if run_id.startswith("bt-"):
            try:
                run_date = datetime.fromisoformat(run_id[3:]).replace(tzinfo=timezone.utc)
                timestamps.append(run_date.timestamp())
            except ValueError:
                pass
        return max(timestamps) if timestamps else None

    def _bt_run_has_only_unanswered_pending(
        self, run_id: str, *, now: Optional[float] = None
    ) -> bool:
        now = time.time() if now is None else now
        pending = [
            forecast
            for forecast in self.pending.values()
            if forecast.get("source") == "bt_forecast"
            and str(forecast.get("run_id")) == run_id
            and self._forecast_open(forecast, now)
        ]
        if not pending:
            return False
        return all(forecast.get("probability") is None for forecast in pending)

    def _bt_run_has_unanswered_pending(
        self, run_id: str, *, now: Optional[float] = None
    ) -> bool:
        now = time.time() if now is None else now
        return any(
            forecast.get("source") == "bt_forecast"
            and str(forecast.get("run_id")) == run_id
            and self._forecast_open(forecast, now)
            and forecast.get("probability") is None
            for forecast in self.pending.values()
        )

    def _bt_question_has_unanswered_pending(
        self,
        run_id: str,
        question_key: str,
        *,
        now: Optional[float] = None,
    ) -> bool:
        now = time.time() if now is None else now
        return any(
            forecast.get("source") == "bt_forecast"
            and str(forecast.get("run_id")) == run_id
            and str(forecast.get("question_key")) == question_key
            and self._forecast_open(forecast, now)
            and forecast.get("probability") is None
            for forecast in self.pending.values()
        )

    def _bt_unanswered_uids_for_question(
        self,
        run_id: str,
        question_key: str,
        miner_uids: list[int],
        *,
        now: Optional[float] = None,
    ) -> list[int]:
        now = time.time() if now is None else now
        has_open_pending = any(
            forecast.get("source") == "bt_forecast"
            and str(forecast.get("run_id")) == run_id
            and str(forecast.get("question_key")) == question_key
            and self._forecast_open(forecast, now)
            for forecast in self.pending.values()
        )
        if not has_open_pending:
            return []

        retry_uids: list[int] = []
        for uid in miner_uids:
            fid = self._bt_pending_key(run_id, question_key, int(uid))
            forecast = self.pending.get(fid)
            if forecast is None:
                retry_uids.append(int(uid))
                continue
            if (
                forecast.get("source") == "bt_forecast"
                and self._forecast_open(forecast, now)
                and forecast.get("probability") is None
            ):
                retry_uids.append(int(uid))
        return retry_uids

    @staticmethod
    def _forecast_open(forecast: dict, now: float) -> bool:
        try:
            return float(forecast.get("resolve_at") or 0.0) > now
        except (AttributeError, TypeError, ValueError):
            return False

    def _bt_no_answer_retry_due(
        self, run_id: str, run_state: dict[str, Any], now: float
    ) -> bool:
        if not self._bt_run_has_only_unanswered_pending(run_id, now=now):
            return False
        return self._bt_unanswered_retry_due(run_id, run_state, now)

    def _bt_unanswered_retry_due(
        self, run_id: str, run_state: dict[str, Any], now: float
    ) -> bool:
        if not self._bt_run_has_unanswered_pending(run_id, now=now):
            return False
        last_attempt = _parse_timestamp(
            str(
                run_state.get("last_unanswered_retry_at")
                or run_state.get("questions_issued_at")
                or ""
            )
        )
        if last_attempt is None:
            return True
        retry_seconds = self._bt_unanswered_retry_delay_seconds(run_id, now=now)
        return now - last_attempt >= retry_seconds

    def _bt_unanswered_retry_base_seconds(self) -> float:
        return max(
            0.0,
            _env_float(
                C.BT_FORECAST_NO_ANSWER_RETRY_SECONDS_ENV,
                C.BT_FORECAST_NO_ANSWER_RETRY_SECONDS,
            ),
        )

    def _bt_unanswered_retry_delay_seconds(
        self, run_id: str, *, now: Optional[float] = None
    ) -> float:
        """Back off retries while keeping them active until the question cutoff."""
        now = time.time() if now is None else now
        base_seconds = self._bt_unanswered_retry_base_seconds()
        max_seconds = max(
            base_seconds,
            _env_float(
                C.BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS_ENV,
                C.BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS,
            ),
        )
        multiplier = max(
            1.0,
            _env_float(
                C.BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER_ENV,
                C.BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER,
            ),
        )
        attempts = []
        for forecast in self.pending.values():
            if (
                forecast.get("source") != "bt_forecast"
                or str(forecast.get("run_id")) != run_id
                or forecast.get("probability") is not None
            ):
                continue
            try:
                resolve_at = float(forecast.get("resolve_at") or 0.0)
            except (TypeError, ValueError):
                continue
            if resolve_at <= now:
                continue
            try:
                attempts.append(int(forecast.get("attempt_count") or 1))
            except (TypeError, ValueError):
                attempts.append(1)
        if not attempts or base_seconds <= 0.0:
            return base_seconds
        delay = base_seconds * (multiplier ** max(0, max(attempts) - 1))
        return min(max_seconds, delay)

    @staticmethod
    def _bt_run_generation_complete(generation: Optional[str]) -> bool:
        return (generation or "").strip().lower() == C.BT_FORECAST_COMPLETE_GENERATION

    @staticmethod
    def _bt_run_poll_after_seconds(value: Optional[int]) -> int:
        try:
            seconds = int(value) if value is not None else C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
        except (TypeError, ValueError):
            seconds = C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
        return max(60, seconds)

    @staticmethod
    def _bt_serialize_question(question: BtForecastQuestion) -> dict[str, Any]:
        return question.model_dump()

    @staticmethod
    def _bt_cached_questions(run_state: dict[str, Any]) -> Optional[list[BtForecastQuestion]]:
        cached = run_state.get("questions")
        if not isinstance(cached, list):
            return None
        questions = []
        for item in cached:
            if not isinstance(item, dict):
                return None
            try:
                questions.append(BtForecastQuestion.model_validate(item))
            except Exception:
                return None
        return questions

    def build_bt_forecast_synapse(self, question: BtForecastQuestion, *, run_id: str) -> ForecastSynapse:
        issued_at = time.time()
        resolve_at = parse_api_timestamp(question.cutoff_date) or issued_at
        context = "\n".join(
            part
            for part in (
                question.evidence_summary,
                question.resolution_criteria,
                f"Measurement: {json.dumps(question.measurement, sort_keys=True)}"
                if question.measurement
                else "",
                f"BT-Forecast run: {run_id}",
            )
            if part
        )
        return ForecastSynapse(
            forecast_id=uuid.uuid4().hex,
            question_id=question.question_id,
            question_key=question.question_key,
            question=question.question,
            event_type=ForecastEventType.SIGNIFICANT_BITTENSOR_EVENT.value,
            family=question.family,
            scope=question.scope,
            netuid=question.netuid,
            horizon_days=question.horizon_days,
            forecast_window=f"{question.horizon_days}d" if question.horizon_days else "",
            issued_at=issued_at,
            resolve_at=resolve_at,
            context=context,
        )

    def _should_issue_bt_question(self, question: BtForecastQuestion, *, now: float) -> bool:
        cutoff_ts = parse_api_timestamp(question.cutoff_date)
        if cutoff_ts is not None and cutoff_ts <= now:
            return False
        reissue_seconds = _env_float(
            C.BT_FORECAST_REISSUE_SECONDS_ENV,
            C.BT_FORECAST_REISSUE_SECONDS,
        )
        last_issued = self.issued_questions.get(question.question_key)
        if last_issued is None:
            return True
        if reissue_seconds <= 0:
            return False
        return now - last_issued >= reissue_seconds

    def _store_bt_forecast_responses(
        self,
        *,
        run_id: str,
        question: BtForecastQuestion,
        synapse: ForecastSynapse,
        miner_uids: list[int],
        responses,
    ) -> tuple[int, int]:
        submitted_at = time.time()
        issued = 0
        answered = 0
        response_list = list(responses or [])
        for index, uid in enumerate(miner_uids):
            resp = response_list[index] if index < len(response_list) else None
            fid = self._bt_pending_key(run_id, question.question_key, int(uid))
            existing = self.pending.get(fid, {})
            try:
                first_issued_at = float(existing.get("issued_at", synapse.issued_at))
            except (TypeError, ValueError):
                first_issued_at = synapse.issued_at
            probability, prediction, confidence = self._normalize_miner_response(resp)
            if probability is not None:
                answered += 1
            if existing.get("probability") is not None and probability is None:
                existing["last_queried_at"] = synapse.issued_at
                existing["attempt_count"] = int(existing.get("attempt_count") or 0) + 1
                self.pending[fid] = existing
                issued += 1
                continue
            self.pending[fid] = {
                "source": "bt_forecast",
                "pending_key": fid,
                "uid": int(uid),
                "hotkey": self.metagraph.hotkeys[int(uid)],
                "forecast_id": getattr(resp, "forecast_id", "") or synapse.forecast_id,
                "question_id": question.question_id,
                "question_key": question.question_key,
                "question": question.question,
                "event_type": ForecastEventType.SIGNIFICANT_BITTENSOR_EVENT.value,
                "family": question.family,
                "scope": question.scope,
                "netuid": question.netuid,
                "horizon_days": question.horizon_days,
                "prediction": prediction,
                "confidence": confidence,
                "probability": probability,
                "reasoning": getattr(resp, "reasoning", ""),
                "model": getattr(resp, "model", "") or "no-response",
                "features": dict(getattr(resp, "features", {}) or {}),
                "timestamp": getattr(resp, "timestamp", ""),
                "submitted_at": _parse_timestamp(getattr(resp, "timestamp", "")) or submitted_at,
                "issued_at": first_issued_at,
                "last_queried_at": synapse.issued_at,
                "attempt_count": int(existing.get("attempt_count") or 0) + 1,
                "resolve_at": synapse.resolve_at,
                "cutoff_date": question.cutoff_date,
                "run_id": run_id,
                "engine_probability": question.engine_probability,
                "measurement": question.measurement,
            }
            issued += 1
        return issued, answered

    @staticmethod
    def _bt_pending_key(run_id: str, question_key: str, uid: int) -> str:
        digest = hashlib.sha256(f"{run_id}\n{question_key}\n{int(uid)}".encode("utf-8")).hexdigest()
        return f"bt_forecast:{digest}"

    def _normalize_miner_response(self, resp) -> tuple[Optional[float], Optional[bool], Optional[float]]:
        if Validator._is_no_answer_model(getattr(resp, "model", "")):
            return None, None, None

        probability = getattr(resp, "probability", None)
        prediction = getattr(resp, "prediction", None)
        confidence = getattr(resp, "confidence", None)
        try:
            probability = float(probability) if probability is not None else None
        except (TypeError, ValueError):
            probability = None

        if probability is not None:
            probability = max(0.0, min(1.0, probability))
            if prediction is None:
                prediction = probability >= C.NEUTRAL_PROB
            if confidence is None:
                confidence = max(probability, 1.0 - probability)
        elif prediction is not None and confidence is not None:
            try:
                c = float(confidence)
                probability = c if bool(prediction) else 1.0 - c
            except (TypeError, ValueError):
                probability = None

        try:
            confidence = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        if confidence is not None:
            confidence = max(0.0, min(1.0, confidence))
        return probability, prediction if prediction is None else bool(prediction), confidence

    @staticmethod
    def _is_no_answer_model(model: Any) -> bool:
        return str(model or "").startswith("baseline")

    def _build_miner_results_payload(
        self,
        *,
        run_id: str,
        question_key: str,
        forecasts: list[dict],
        resolution: BtForecastResolution,
        outcome: bool,
    ) -> dict[str, Any]:
        sample = forecasts[0] if forecasts else {}
        threshold = _env_float(
            C.BT_FORECAST_FEEDBACK_THRESHOLD_ENV,
            C.BT_FORECAST_FEEDBACK_THRESHOLD,
        )
        outcome_value = float(outcome)
        engine_probability = sample.get("engine_probability")
        results = []
        for forecast in forecasts:
            probability = forecast.get("probability")
            if probability is None:
                continue
            probability = float(probability)
            dist_to_outcome = abs(probability - outcome_value)
            if dist_to_outcome > threshold:
                continue
            dist_to_engine = (
                abs(probability - float(engine_probability))
                if engine_probability is not None
                else None
            )
            results.append(
                {
                    "uid": int(forecast["uid"]),
                    "hotkey": forecast.get("hotkey", ""),
                    "probability": probability,
                    "prediction": forecast.get("prediction"),
                    "confidence": forecast.get("confidence"),
                    "reasoning": forecast.get("reasoning", ""),
                    "model": forecast.get("model", ""),
                    "features": dict(forecast.get("features") or {}),
                    "issued_at": forecast.get("issued_at"),
                    "submitted_at": forecast.get("submitted_at"),
                    "brier": brier_score(probability, outcome),
                    "dist_to_outcome": dist_to_outcome,
                    "dist_to_engine": dist_to_engine,
                }
            )
        return {
            "run_id": run_id,
            "question_key": question_key,
            "family": sample.get("family") or resolution.family,
            "scope": sample.get("scope") or resolution.scope,
            "netuid": sample.get("netuid", resolution.netuid),
            "horizon_days": sample.get("horizon_days", resolution.horizon_days),
            "outcome": outcome,
            "measurement_value": resolution.measurement_value,
            "resolved_at": resolution.resolved_at or datetime.now(timezone.utc).isoformat(),
            "engine_probability": engine_probability,
            "results": results,
        }

    def _bt_forecast_client(self):
        client = getattr(self, "bt_forecast_client", None)
        if client is None:
            client = open_bt_forecast_client_from_env()
            self.bt_forecast_client = client
        return client

    def _bt_forecast_required(self) -> bool:
        if not hasattr(self, "bt_forecast_required"):
            self.bt_forecast_required = bt_forecast_required_from_env()
        return bool(self.bt_forecast_required)

    def get_miner_uids(self) -> list[int]:
        """All registered neurons that are serving an axon (i.e., miners)."""
        uids = []
        query_validators = _env_flag(C.QUERY_VALIDATOR_UIDS_ENV, False)
        validator_permit = getattr(self.metagraph, "validator_permit", None)
        for uid in range(self._metagraph_size()):
            if not self.metagraph.axons[uid].is_serving:
                continue
            if self.metagraph.hotkeys[uid] == self.wallet.hotkey.ss58_address:
                continue
            if (
                not query_validators
                and validator_permit is not None
                and bool(validator_permit[uid])
            ):
                continue
            uids.append(uid)
        return uids

    def _metagraph_size(self) -> int:
        n = getattr(self.metagraph, "n", 0)
        return int(n.item()) if hasattr(n, "item") else int(n)

    # ------------------------------------------------------------- forward
    async def forward(self):
        """One validator step: resolve due → issue new → persist."""
        lock = getattr(self, "lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self.lock = lock
        async with lock:
            await self.resolve_due()
            self.save_masxai_state()
            await self.issue_round()
            self.save_masxai_state()
        # brief pause so we don't hot-loop; the base class also paces by epoch
        await asyncio.sleep(5)


if __name__ == "__main__":
    with Validator() as validator:
        while True:
            thread = getattr(validator, "thread", None)
            if thread is not None and not thread.is_alive():
                bt.logging.error(
                    "MASXAI validator background loop stopped; exiting instead of "
                    "continuing stale alive logs"
                )
                raise SystemExit(1)
            answered_pending = sum(
                1
                for forecast in validator.pending.values()
                if forecast.get("probability") is not None
            )
            no_answer_pending = len(validator.pending) - answered_pending
            bt.logging.info(
                f"MASXAI validator alive | pending={len(validator.pending)} "
                f"answered={answered_pending} no_answer={no_answer_pending} "
                f"resolved={validator.resolved_count} | "
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            time.sleep(30)
