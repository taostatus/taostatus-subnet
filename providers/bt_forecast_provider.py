from __future__ import annotations

"""BT-Forecast task provider backed by daily forecast runs."""

import json
import time
from typing import Any, Optional

from masxai import constants as C
from masxai.oracle_bt import (
    BtForecastClient,
    BtForecastQuestion,
    bt_forecast_run_id_from_env,
    parse_api_datetime,
)
from config import Settings
from models import SyncState, as_utc, utcnow
from providers.base import ProviderTask


class BTForecastTaskProvider:
    def __init__(self, settings: Settings, session_factory):
        self.settings = settings
        self.session_factory = session_factory

    async def fetch_tasks(self) -> list[ProviderTask]:
        run_id = bt_forecast_run_id_from_env()
        state_key = f"bt_forecast:run:{run_id}"
        state = self._read_json_state(state_key)
        now = time.time()

        if state.get("questions_fetched_at"):
            return []

        next_poll_at = float(state.get("next_poll_at") or 0.0)
        if next_poll_at > now:
            return []

        client = BtForecastClient(
            base_url=self.settings.bt_forecast_base_url,
            bearer_token=self.settings.bt_forecast_bearer_token,
            timeout=self.settings.bt_forecast_request_timeout_seconds,
            max_retries=self.settings.bt_forecast_max_retries,
        )
        run = await client.get_run(run_id)
        state.update(
            {
                "run_id": run.run_id,
                "status": run.status,
                "generation": run.generation,
                "question_count": run.question_count,
                "ready_at": run.ready_at,
                "template_version": run.template_version,
                "measurement_version": run.measurement_version,
                "last_polled_at": utcnow().isoformat(),
            }
        )

        if (run.generation or "").lower() != C.BT_FORECAST_COMPLETE_GENERATION:
            poll_after_s = self._poll_after_seconds(run.poll_after_s)
            state["poll_after_s"] = poll_after_s
            state["next_poll_at"] = now + poll_after_s
            self._write_state(state_key, value=json.dumps(state, sort_keys=True))
            return []

        questions = await client.get_questions(run_id, include_lineage=False)
        tasks = [
            self._normalize_question(run_id, question)
            for question in questions
            if not question.predetermined_at_creation
        ]
        state["questions_fetched_at"] = utcnow().isoformat()
        state["question_keys"] = [question.question_key for question in questions]
        state["stored_question_count"] = len(tasks)
        state["next_poll_at"] = None
        self._write_state(state_key, value=json.dumps(state, sort_keys=True))
        return tasks

    def _normalize_question(self, run_id: str, question: BtForecastQuestion) -> ProviderTask:
        now = utcnow()
        deadline = parse_api_datetime(question.cutoff_date) or now
        generated_at = parse_api_datetime(question.generated_at) or now
        resolution_hint = "\n".join(
            part
            for part in (
                question.evidence_summary,
                question.resolution_criteria,
                f"Measurement: {json.dumps(question.measurement, sort_keys=True)}"
                if question.measurement
                else "",
                f"BT-Forecast run: {run_id}",
                f"Question key: {question.question_key}",
            )
            if part
        )
        return ProviderTask(
            task_id=f"{run_id}:{question.question_key}",
            question=question.question,
            category=C.SIGNIFICANT_BITTENSOR_EVENT,
            deadline=as_utc(deadline),
            resolution_hint=resolution_hint,
            source="bt_forecast",
            schema_version="bt-forecast-v1",
            created_at=generated_at,
            updated_at=now,
        )

    def _read_json_state(self, key: str) -> dict[str, Any]:
        raw = self._read_state(key).value
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _poll_after_seconds(value: Optional[int]) -> int:
        try:
            seconds = int(value) if value is not None else C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
        except (TypeError, ValueError):
            seconds = C.BT_FORECAST_DEFAULT_POLL_AFTER_SECONDS
        return max(60, seconds)

    def _read_state(self, key: str) -> SyncState:
        with self.session_factory() as session:
            state = session.get(SyncState, key)
            if state is None:
                return SyncState(key=key, value=None, etag=None, updated_at=utcnow())
            return state

    def _write_state(
        self, key: str, value: Optional[str] = None, etag: Optional[str] = None
    ) -> None:
        with self.session_factory() as session:
            state = session.get(SyncState, key)
            if state is None:
                state = SyncState(key=key)
                session.add(state)
            state.value = value
            if etag is not None:
                state.etag = etag
            state.updated_at = utcnow()
            session.commit()
