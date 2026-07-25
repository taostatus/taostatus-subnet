from __future__ import annotations

import asyncio
from types import SimpleNamespace

import numpy as np
import pytest

from masxai.oracle_bt import (
    BtForecastClient,
    BtForecastQuestion,
    BtForecastResolution,
    BtForecastRunStatus,
)
from masxai import constants as C
from neurons.validator import BaseValidatorNeuron, Validator
from providers.bt_forecast_provider import BTForecastTaskProvider


class _FakeAxon:
    def __init__(self, hotkey: str):
        self.hotkey = hotkey
        self.is_serving = True


class _FakeMetagraph:
    hotkeys = ["validator-hotkey", "miner-hotkey-1", "miner-hotkey-2"]
    n = np.int64(3)

    def __init__(self):
        self.axons = [_FakeAxon(hotkey) for hotkey in self.hotkeys]


class _FakeWallet:
    hotkey = SimpleNamespace(ss58_address="validator-hotkey")


class _FakeDendrite:
    def __init__(self):
        self.synapses = []
        self.axon_batches = []

    async def __call__(self, axons, synapse, deserialize=False, timeout=0):
        self.synapses.append(synapse)
        self.axon_batches.append([axon.hotkey for axon in axons])
        responses = []
        for axon in axons:
            resp = synapse.model_copy(deep=True)
            resp.probability = 0.93 if axon.hotkey.endswith("1") else 0.40
            resp.prediction = resp.probability >= 0.5
            resp.confidence = max(resp.probability, 1.0 - resp.probability)
            resp.reasoning = "central BT-Forecast test response"
            resp.timestamp = "2026-07-16T00:00:00+00:00"
            resp.model = "fake"
            responses.append(resp)
        return responses


class _FakeBtForecastClient:
    def __init__(self, *, generation: str = "complete", poll_after_s: int = 3600):
        self.generation = generation
        self.poll_after_s = poll_after_s
        self.run_polls = 0
        self.question_fetches = 0
        self.posts = []
        self.include_lineage_calls = []

    async def get_run(self, run_id: str):
        self.run_polls += 1
        return BtForecastRunStatus(
            run_id=run_id,
            status="ready",
            generation=self.generation,
            question_count=1,
            poll_after_s=self.poll_after_s,
        )

    async def get_questions(self, run_id: str, include_lineage: bool = False):
        self.question_fetches += 1
        self.include_lineage_calls.append(include_lineage)
        return [
            BtForecastQuestion(
                question_id="pred-1",
                question_key="Will SN12 active miner count fall below by daily snapshot|SN12|2099-01-01",
                question="Will SN12 active miner count fall below 128 by 2099-01-01?",
                family="active_miners",
                scope="subnet",
                netuid=12,
                horizon_days=14,
                cutoff_date="2099-01-01T06:00:00Z",
                resolution_criteria="Resolved from the daily on-chain snapshot.",
                evidence_summary="SN12 miners 141 -> 133 over 7d.",
                measurement={"threshold": 128, "operator": "below"},
                engine_probability=0.31 if include_lineage else None,
            )
        ]

    async def get_resolutions(self, run_id: str):
        return [
            BtForecastResolution(
                question_key="Will SN12 active miner count fall below by daily snapshot|SN12|2099-01-01",
                status="resolved_true",
                outcome=True,
                resolved_at="2099-01-01T06:04:10Z",
                measurement_value=126,
            )
        ]

    async def post_miner_results(self, payload):
        self.posts.append(payload)
        return {"ok": True}


def _validator(fake_client: _FakeBtForecastClient) -> Validator:
    validator = Validator.__new__(Validator)
    validator.pending = {}
    validator.issued_questions = {}
    validator.feedback_queue = []
    validator.bt_forecast_runs = {}
    validator.bt_forecast_client = fake_client
    validator.bt_forecast_required = True
    validator.resolved_count = 0
    validator.last_issue_at = 0.0
    validator.metagraph = _FakeMetagraph()
    validator.wallet = _FakeWallet()
    validator.dendrite = _FakeDendrite()
    validator.scores = np.zeros(3, dtype=np.float32)
    return validator


def test_validator_issues_bt_forecast_question_without_engine_answer(monkeypatch):
    monkeypatch.setenv("MASXAI_FORECAST_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    monkeypatch.setenv("BT_FORECAST_INCLUDE_LINEAGE", "true")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)

    asyncio.run(validator.issue_round())

    assert len(validator.pending) == 2
    synapse = validator.dendrite.synapses[0]
    assert synapse.question_key
    assert synapse.family == "active_miners"
    assert synapse.netuid == 12
    assert synapse.horizon_days == 14
    assert "0.31" not in synapse.context
    assert validator.bt_forecast_runs["bt-test"]["questions"][0]["question_key"] == synapse.question_key
    assert validator._bt_pending_key("bt-test", synapse.question_key, 1) in validator.pending
    assert validator._bt_pending_key("bt-test", synapse.question_key, 2) in validator.pending


def test_bt_forecast_client_uses_only_bearer_auth_header():
    client = BtForecastClient(base_url="https://bt-forecast.example", bearer_token="secret-token")

    assert client._auth_headers() == {"Authorization": "Bearer secret-token"}


def test_bt_forecast_client_requires_bearer_token():
    with pytest.raises(ValueError, match="BT_FORECAST_BEARER_TOKEN"):
        BtForecastClient(base_url="https://bt-forecast.example")


def test_bt_forecast_task_provider_normalizes_run_question_for_db():
    provider = BTForecastTaskProvider(settings=SimpleNamespace(), session_factory=lambda: None)
    task = provider._normalize_question(
        "bt-test",
        BtForecastQuestion(
            question_id="q-1",
            question_key="active_miners|SN12|2099-01-01",
            question="Will SN12 active miner count fall below 128 by 2099-01-01?",
            family="active_miners",
            scope="subnet",
            netuid=12,
            horizon_days=14,
            cutoff_date="2099-01-01T06:00:00Z",
            resolution_criteria="Resolved from the daily on-chain snapshot.",
            evidence_summary="SN12 miners 141 -> 133 over 7d.",
            measurement={"threshold": 128, "operator": "below"},
            generated_at="2098-12-18T06:00:00Z",
        ),
    )

    assert task.task_id == "bt-test:active_miners|SN12|2099-01-01"
    assert task.category == C.SIGNIFICANT_BITTENSOR_EVENT
    assert task.source == "bt_forecast"
    assert "BT-Forecast run: bt-test" in task.resolution_hint


def test_validator_waits_for_generation_complete_before_fetching_questions(monkeypatch):
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    fake_client = _FakeBtForecastClient(generation="running", poll_after_s=3600)
    validator = _validator(fake_client)

    asyncio.run(validator.issue_round())
    asyncio.run(validator.issue_round())

    assert fake_client.run_polls == 1
    assert fake_client.question_fetches == 0
    assert validator.pending == {}
    assert validator.bt_forecast_runs["bt-test"]["generation"] == "running"
    assert validator.bt_forecast_runs["bt-test"]["poll_after_s"] == 3600


def test_validator_retries_bt_run_when_previous_issue_had_no_answers(monkeypatch):
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    question = asyncio.run(fake_client.get_questions("bt-test"))[0]
    pending_key = validator._bt_pending_key("bt-test", question.question_key, 1)
    validator.bt_forecast_runs["bt-test"] = {
        "generation": "complete",
        "questions": [question.model_dump()],
        "questions_issued_at": "1970-01-01T00:00:00+00:00",
        "issued_question_count": 1,
        "last_issue_answered_count": 0,
    }
    validator.issued_questions[question.question_key] = 1.0
    validator.pending[pending_key] = {
        "source": "bt_forecast",
        "run_id": "bt-test",
        "uid": 1,
        "question_key": question.question_key,
        "probability": None,
        "resolve_at": 2_000.0,
    }

    asyncio.run(validator.issue_bt_forecast_round(client=fake_client, now=1_000.0))

    assert len(validator.dendrite.synapses) == 1
    assert validator.pending[pending_key]["probability"] == 0.93
    assert validator.bt_forecast_runs["bt-test"]["last_issue_answered_count"] == 2


def test_validator_waits_before_retrying_zero_answer_bt_run(monkeypatch):
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    question = asyncio.run(fake_client.get_questions("bt-test"))[0]
    pending_key = validator._bt_pending_key("bt-test", question.question_key, 1)
    validator.bt_forecast_runs["bt-test"] = {
        "generation": "complete",
        "questions": [question.model_dump()],
        "questions_issued_at": "1970-01-01T00:15:00+00:00",
        "issued_question_count": 1,
        "last_issue_answered_count": 0,
    }
    validator.pending[pending_key] = {
        "source": "bt_forecast",
        "run_id": "bt-test",
        "uid": 1,
        "question_key": question.question_key,
        "probability": None,
        "resolve_at": 2_000.0,
    }

    asyncio.run(validator.issue_bt_forecast_round(client=fake_client, now=1_000.0))

    assert validator.dendrite.synapses == []
    assert validator.pending[pending_key]["probability"] is None


def test_validator_retries_only_unanswered_miners(monkeypatch):
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    question = asyncio.run(fake_client.get_questions("bt-test"))[0]
    answered_key = validator._bt_pending_key("bt-test", question.question_key, 1)
    unanswered_key = validator._bt_pending_key("bt-test", question.question_key, 2)
    validator.bt_forecast_runs["bt-test"] = {
        "generation": "complete",
        "questions": [question.model_dump()],
        "questions_issued_at": "1970-01-01T00:00:00+00:00",
        "issued_question_count": 1,
        "last_issue_answered_count": 1,
    }
    validator.pending[answered_key] = {
        "source": "bt_forecast",
        "run_id": "bt-test",
        "uid": 1,
        "question_key": question.question_key,
        "probability": 0.93,
        "prediction": True,
        "confidence": 0.93,
        "resolve_at": 2_000.0,
        "issued_at": 100.0,
        "attempt_count": 1,
    }
    validator.pending[unanswered_key] = {
        "source": "bt_forecast",
        "run_id": "bt-test",
        "uid": 2,
        "question_key": question.question_key,
        "probability": None,
        "resolve_at": 2_000.0,
        "issued_at": 100.0,
        "attempt_count": 1,
    }

    asyncio.run(validator.issue_bt_forecast_round(client=fake_client, now=1_000.0))

    assert validator.dendrite.axon_batches == [["miner-hotkey-2"]]
    assert validator.pending[answered_key]["probability"] == 0.93
    assert validator.pending[answered_key]["attempt_count"] == 1
    assert validator.pending[unanswered_key]["probability"] == 0.40
    assert validator.pending[unanswered_key]["issued_at"] == 100.0
    assert validator.pending[unanswered_key]["attempt_count"] == 2


def test_validator_retries_unanswered_older_open_runs(monkeypatch):
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-current")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    question = asyncio.run(fake_client.get_questions("bt-old"))[0]
    pending_key = validator._bt_pending_key("bt-old", question.question_key, 1)
    validator.bt_forecast_runs["bt-old"] = {
        "generation": "complete",
        "questions": [question.model_dump()],
        "questions_issued_at": "1970-01-01T00:00:00+00:00",
        "issued_question_count": 1,
        "last_issue_answered_count": 0,
    }
    validator.pending[pending_key] = {
        "source": "bt_forecast",
        "run_id": "bt-old",
        "uid": 1,
        "question_key": question.question_key,
        "probability": None,
        "resolve_at": 2_000.0,
        "issued_at": 100.0,
    }

    asyncio.run(
        validator.retry_unanswered_bt_forecast_runs(
            client=fake_client,
            now=1_000.0,
            exclude_run_id="bt-current",
        )
    )

    assert validator.dendrite.axon_batches == [["miner-hotkey-1", "miner-hotkey-2"]]
    assert validator.pending[pending_key]["probability"] == 0.93
    assert validator.bt_forecast_runs["bt-old"]["last_unanswered_retry_at"]


def test_validator_treats_baseline_model_as_no_answer():
    validator = _validator(_FakeBtForecastClient())
    resp = SimpleNamespace(
        probability=0.5,
        prediction=True,
        confidence=0.5,
        model="baseline-after-gemini-error",
    )

    assert validator._normalize_miner_response(resp) == (None, None, None)


def test_validator_sanitizes_persisted_baseline_forecasts():
    validator = _validator(_FakeBtForecastClient())
    validator.pending = {
        "old-fallback": {
            "model": "baseline-after-gemini-error",
            "probability": 0.5,
            "prediction": True,
            "confidence": 0.5,
        },
        "real-answer": {
            "model": "gemini-2.5-flash",
            "probability": 0.7,
            "prediction": True,
            "confidence": 0.7,
        },
    }

    assert validator._sanitize_fallback_pending() == 1
    assert validator.pending["old-fallback"]["probability"] is None
    assert validator.pending["old-fallback"]["prediction"] is None
    assert validator.pending["old-fallback"]["confidence"] is None
    assert validator.pending["real-answer"]["probability"] == 0.7


def test_bt_forecast_resolution_parses_real_api_shape():
    resolution = BtForecastResolution.model_validate(
        {
            "question_key": "dtao_pool|SN99|2026-07-29",
            "family": "dtao_pool",
            "scope": "subnet",
            "netuid": 99,
            "horizon_days": 6,
            "status": "open",
            "outcome": None,
            "cutoff_date": "2026-07-29T00:00:00+00:00",
            "resolved_at": None,
            "measurement": {
                "source": "daily_snapshot",
                "grade_time_utc": "06:00",
                "threshold": 1299,
                "threshold_unit": "tao",
                "operator": "below",
            },
            "measurement_value": None,
            "observed_at": None,
            "explanation": None,
            "engine_brier": None,
            "deferral_reason": None,
        }
    )

    assert resolution.family == "dtao_pool"
    assert resolution.netuid == 99
    assert resolution.measurement["threshold"] == 1299
    assert resolution.bool_outcome() is None


def test_miner_results_payload_matches_api_request_shape():
    validator = _validator(_FakeBtForecastClient())
    resolution = BtForecastResolution(
        question_key="dtao_pool|SN99|2026-07-29",
        family="dtao_pool",
        scope="subnet",
        netuid=99,
        horizon_days=6,
        status="resolved_true",
        outcome=True,
        resolved_at="2026-07-29T06:04:10+00:00",
        measurement_value=1100,
    )
    payload = validator._build_miner_results_payload(
        run_id="bt-2026-07-22",
        question_key="dtao_pool|SN99|2026-07-29",
        forecasts=[
            {
                "uid": 1,
                "hotkey": "miner-hotkey-1",
                "probability": 0.93,
                "prediction": True,
                "confidence": 0.93,
                "reasoning": "Pool likely stays thin.",
                "model": "fake",
                "features": {},
                "issued_at": 1.0,
                "submitted_at": 2.0,
                "engine_probability": None,
            }
        ],
        resolution=resolution,
        outcome=True,
    )

    assert payload["run_id"] == "bt-2026-07-22"
    assert payload["question_key"] == "dtao_pool|SN99|2026-07-29"
    assert payload["family"] == "dtao_pool"
    assert payload["scope"] == "subnet"
    assert payload["netuid"] == 99
    assert payload["horizon_days"] == 6
    assert payload["outcome"] is True
    assert payload["measurement_value"] == 1100
    assert payload["resolved_at"] == "2026-07-29T06:04:10+00:00"
    assert payload["engine_probability"] is None
    assert payload["results"][0]["uid"] == 1
    assert payload["results"][0]["probability"] == 0.93
    assert payload["results"][0]["dist_to_engine"] is None


def test_validator_lineage_is_opt_in_by_default(monkeypatch):
    monkeypatch.setenv("MASXAI_FORECAST_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    monkeypatch.delenv("BT_FORECAST_INCLUDE_LINEAGE", raising=False)
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)

    asyncio.run(validator.issue_round())

    assert fake_client.include_lineage_calls == [False]
    assert all(item["engine_probability"] is None for item in validator.pending.values())


def test_validator_resolves_bt_forecast_and_posts_accurate_miners(monkeypatch):
    monkeypatch.setenv("MASXAI_FORECAST_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    monkeypatch.setenv("BT_FORECAST_INCLUDE_LINEAGE", "true")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)

    asyncio.run(validator.issue_round())
    for forecast in validator.pending.values():
        forecast["resolve_at"] = 1.0

    asyncio.run(validator.resolve_due())

    assert validator.pending == {}
    assert validator.scores[1] > validator.scores[2]
    assert len(fake_client.posts) == 1
    assert [row["uid"] for row in fake_client.posts[0]["results"]] == [1]
    assert fake_client.posts[0]["engine_probability"] == 0.31


def test_validator_refuses_weights_before_resolved_scores(monkeypatch):
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.scores[1] = 1.0
    called = []
    monkeypatch.setattr(
        BaseValidatorNeuron,
        "set_weights",
        lambda self: called.append("set"),
    )

    assert validator.should_set_weights() is False
    assert validator.set_weights() is None
    assert called == []


def test_validator_refuses_weights_when_scored_miners_below_chain_minimum(monkeypatch):
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.resolved_count = C.MIN_RESOLVED_BEFORE_WEIGHTS
    validator.scores[1] = 0.75
    validator.config = SimpleNamespace(netuid=501)
    validator.subtensor = SimpleNamespace(min_allowed_weights=lambda netuid: 2)
    called = []
    monkeypatch.setattr(
        BaseValidatorNeuron,
        "set_weights",
        lambda self: called.append("set"),
    )

    assert validator.should_set_weights() is False
    assert validator.set_weights() is None
    assert called == []


def test_validator_allows_weights_after_resolved_positive_score(monkeypatch):
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.resolved_count = C.MIN_RESOLVED_BEFORE_WEIGHTS
    validator.scores[1] = 0.75
    called = []
    monkeypatch.setattr(
        BaseValidatorNeuron,
        "should_set_weights",
        lambda self: called.append("should") or True,
    )
    monkeypatch.setattr(
        BaseValidatorNeuron,
        "set_weights",
        lambda self: called.append("set"),
    )

    assert validator.should_set_weights() is True
    assert validator.set_weights() is None
    assert called == ["should", "set"]


def test_validator_skips_validator_permit_uids_by_default(monkeypatch):
    monkeypatch.delenv("MASXAI_QUERY_VALIDATOR_UIDS", raising=False)
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.metagraph.validator_permit = np.array([True, False, True])

    assert validator.get_miner_uids() == [1]


def test_validator_stores_no_response_rows_for_retry(monkeypatch):
    class NoResponseDendrite:
        async def __call__(self, axons, synapse, deserialize=False, timeout=0):
            return []

    monkeypatch.setenv("MASXAI_FORECAST_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("BT_FORECAST_RUN_ID", "bt-test")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.dendrite = NoResponseDendrite()

    asyncio.run(validator.issue_round())

    assert len(validator.pending) == 2
    assert all(item["probability"] is None for item in validator.pending.values())
    assert all(item["model"] == "no-response" for item in validator.pending.values())
    assert all(item["attempt_count"] == 1 for item in validator.pending.values())
    assert validator.bt_forecast_runs["bt-test"]["last_issue_answered_count"] == 0


def test_validator_retry_backoff_uses_attempt_count(monkeypatch):
    monkeypatch.setenv("MASXAI_BT_FORECAST_NO_ANSWER_RETRY_SECONDS", "100")
    monkeypatch.setenv("MASXAI_BT_FORECAST_NO_ANSWER_RETRY_MAX_SECONDS", "1000")
    monkeypatch.setenv("MASXAI_BT_FORECAST_NO_ANSWER_RETRY_BACKOFF_MULTIPLIER", "2")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    question = asyncio.run(fake_client.get_questions("bt-test"))[0]
    pending_key = validator._bt_pending_key("bt-test", question.question_key, 1)
    validator.pending[pending_key] = {
        "source": "bt_forecast",
        "run_id": "bt-test",
        "uid": 1,
        "question_key": question.question_key,
        "probability": None,
        "resolve_at": 2_000.0,
        "attempt_count": 3,
    }
    run_state = {"last_unanswered_retry_at": "1970-01-01T00:16:40+00:00"}

    assert validator._bt_unanswered_retry_due("bt-test", run_state, 1_300.0) is False
    assert validator._bt_unanswered_retry_due("bt-test", run_state, 1_400.0) is True


def test_validator_prunes_malformed_stale_and_old_run_state(monkeypatch):
    monkeypatch.setenv("MASXAI_BT_FORECAST_RESOLUTION_WAIT_SECONDS", "10")
    monkeypatch.setenv("MASXAI_BT_FORECAST_RUN_STATE_RETENTION_SECONDS", "10")
    fake_client = _FakeBtForecastClient()
    validator = _validator(fake_client)
    validator.pending = {
        "malformed": {"source": "bt_forecast", "resolve_at": "not-a-time"},
        "stale": {
            "source": "bt_forecast",
            "run_id": "bt-old",
            "resolve_at": 100.0,
        },
        "fresh": {
            "source": "bt_forecast",
            "run_id": "bt-fresh",
            "resolve_at": 1_000.0,
        },
    }
    validator.bt_forecast_runs = {
        "bt-old": {"last_polled_at": "1970-01-01T00:01:40+00:00"},
        "bt-fresh": {"last_polled_at": "1970-01-01T00:10:00+00:00"},
    }

    stats = validator.prune_masxai_state(now=200.0)

    assert stats["malformed_pending"] == 1
    assert stats["stale_pending"] == 1
    assert stats["old_runs"] == 1
    assert set(validator.pending) == {"fresh"}
    assert set(validator.bt_forecast_runs) == {"bt-fresh"}


def test_validator_weight_gate_is_configurable(monkeypatch):
    monkeypatch.setenv("MASXAI_MIN_RESOLVED_BEFORE_WEIGHTS", "5")
    validator = _validator(_FakeBtForecastClient())
    validator.scores[1] = 0.75
    validator.resolved_count = 4

    assert validator._has_scored_weights() is False

    validator.resolved_count = 5

    assert validator._has_scored_weights() is True
