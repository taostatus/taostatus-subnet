from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import numpy as np

from masxai.scoring import brier_score
from neurons.validator import Validator


class _FakeIngestMetagraph:
    def __init__(self):
        self.hotkeys = ["hotkey-0", "hotkey-1"]
        self.coldkeys = ["cold-0", "cold-1"]
        self.stake = [10.0, 20.0]
        self.incentive = [0.1, 0.2]
        self.active = [1, 0]
        # Deliberately no .trust - some bittensor versions don't expose it on
        # the metagraph, and the payload builder must degrade gracefully.


class _FakeIngestClient:
    def __init__(self):
        self.upsert_calls: list[dict] = []
        self.submit_calls: list[tuple] = []
        self.resolve_calls: list[tuple] = []
        self.submit_result: dict = {"id": "activity-1"}
        self.submit_error: Exception | None = None
        self.resolve_error: Exception | None = None

    async def upsert_miner(self, payload):
        self.upsert_calls.append(payload)
        return {}

    async def submit_activity(self, hotkey, payload):
        self.submit_calls.append((hotkey, payload))
        if self.submit_error is not None:
            raise self.submit_error
        return self.submit_result

    async def resolve_activity(self, hotkey, activity_id, payload):
        self.resolve_calls.append((hotkey, activity_id, payload))
        if self.resolve_error is not None:
            raise self.resolve_error
        return {}


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://ingest.example.test/x")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError("error", request=request, response=response)


def _validator(ingest_client) -> Validator:
    validator = Validator.__new__(Validator)
    validator.pending = {}
    validator.ingest_client = ingest_client
    validator.ingest_submit_queue = []
    validator.ingest_resolve_queue = []
    validator.ingest_registered_hotkeys = set()
    validator.last_miner_registry_sync_at = 0.0
    validator.metagraph = _FakeIngestMetagraph()
    validator.config = SimpleNamespace(netuid=501)
    validator.scores = np.zeros(2, dtype=np.float32)
    return validator


def _forecast(**overrides) -> dict:
    forecast = {
        "uid": 0,
        "hotkey": "hotkey-0",
        "forecast_id": "fc-1",
        "event_type": "significant_bittensor_event",
        "prediction": True,
        "confidence": 0.8,
        "probability": 0.73,
        "reasoning": "because",
        "model": "masxai-v3",
        "issued_at": 1_000.0,
        "submitted_at": 1_002.0,
        "resolve_at": 2_000.0,
    }
    forecast.update(overrides)
    return forecast


# --------------------------------------------------------------- payload build


def test_build_activity_payload_maps_known_event_type():
    validator = _validator(_FakeIngestClient())

    payload = validator._build_activity_payload(_forecast())

    assert payload["eventType"] == "significant_bittensor_event"
    assert payload["forecastId"] == "fc-1"
    assert payload["questionKey"] == "fc-1"
    assert payload["prediction"] is True
    assert payload["probability"] == 0.73
    assert payload["isNoAnswer"] is False
    assert payload["responseTimeMs"] == 2000
    assert payload["resolveAt"] == "1970-01-01T00:33:20+00:00"
    assert payload["submittedAt"] == "1970-01-01T00:16:42+00:00"


def test_build_activity_payload_falls_back_to_other_for_unknown_event_type():
    validator = _validator(_FakeIngestClient())

    payload = validator._build_activity_payload(_forecast(event_type="not_a_real_type"))

    assert payload["eventType"] == "other"


def test_build_activity_payload_marks_no_answer():
    validator = _validator(_FakeIngestClient())
    forecast = _forecast(probability=None, prediction=None, confidence=None)

    payload = validator._build_activity_payload(forecast)

    assert payload["isNoAnswer"] is True
    assert "probability" not in payload


# --------------------------------------------------------------- queueing


def test_queue_ingest_submission_is_noop_when_unconfigured():
    validator = _validator(None)

    validator._queue_ingest_submission("fid-1", _forecast())

    assert validator.ingest_submit_queue == []


def test_queue_ingest_submission_appends_when_configured():
    validator = _validator(_FakeIngestClient())

    validator._queue_ingest_submission("fid-1", _forecast())

    assert len(validator.ingest_submit_queue) == 1
    item = validator.ingest_submit_queue[0]
    assert item["fid"] == "fid-1"
    assert item["hotkey"] == "hotkey-0"


def test_queue_ingest_resolution_skips_without_activity_id():
    validator = _validator(_FakeIngestClient())

    validator._queue_ingest_resolution(_forecast(), outcome=True, reward=0.8)

    assert validator.ingest_resolve_queue == []


def test_queue_ingest_resolution_includes_brier_score():
    validator = _validator(_FakeIngestClient())
    forecast = _forecast(ingest_activity_id="activity-1")

    validator._queue_ingest_resolution(forecast, outcome=True, reward=0.8)

    assert len(validator.ingest_resolve_queue) == 1
    item = validator.ingest_resolve_queue[0]
    assert item["hotkey"] == "hotkey-0"
    assert item["activity_id"] == "activity-1"
    assert item["payload"]["outcome"] is True
    assert item["payload"]["rewardComposite"] == 0.8
    assert item["payload"]["brierScore"] == brier_score(0.73, True)


def test_queue_bounding_drops_oldest(monkeypatch):
    monkeypatch.setenv("MASXAI_INGEST_QUEUE_MAX", "2")
    validator = _validator(_FakeIngestClient())

    for i in range(5):
        validator._queue_ingest_submission(f"fid-{i}", _forecast(hotkey=f"hotkey-{i}"))

    assert len(validator.ingest_submit_queue) == 2
    assert [item["fid"] for item in validator.ingest_submit_queue] == ["fid-3", "fid-4"]


# --------------------------------------------------------------- flush


def test_flush_ingest_submissions_writes_activity_id_into_pending():
    client = _FakeIngestClient()
    validator = _validator(client)
    validator.pending["fid-1"] = _forecast()
    validator.ingest_submit_queue = [
        {"fid": "fid-1", "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    ]

    asyncio.run(validator.flush_ingest_submissions())

    assert validator.ingest_submit_queue == []
    assert validator.pending["fid-1"]["ingest_activity_id"] == "activity-1"
    assert client.submit_calls == [("hotkey-0", {"eventType": "other"})]


def test_flush_ingest_submissions_requeues_on_retryable_error():
    client = _FakeIngestClient()
    client.submit_error = httpx.ConnectError("boom")
    validator = _validator(client)
    item = {"fid": "fid-1", "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    validator.ingest_submit_queue = [item]

    asyncio.run(validator.flush_ingest_submissions())

    assert validator.ingest_submit_queue == [item]


def test_flush_ingest_submissions_drops_on_client_error():
    client = _FakeIngestClient()
    client.submit_error = _http_status_error(409)
    validator = _validator(client)
    validator.ingest_submit_queue = [
        {"fid": "fid-1", "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    ]

    asyncio.run(validator.flush_ingest_submissions())

    assert validator.ingest_submit_queue == []


def test_flush_ingest_resolutions_drops_on_success():
    client = _FakeIngestClient()
    validator = _validator(client)
    validator.ingest_resolve_queue = [
        {"hotkey": "hotkey-0", "activity_id": "activity-1", "payload": {"outcome": True}}
    ]

    asyncio.run(validator.flush_ingest_resolutions())

    assert validator.ingest_resolve_queue == []
    assert client.resolve_calls == [("hotkey-0", "activity-1", {"outcome": True})]


def test_flush_ingest_resolutions_requeues_on_server_error():
    client = _FakeIngestClient()
    client.resolve_error = _http_status_error(503)
    validator = _validator(client)
    item = {"hotkey": "hotkey-0", "activity_id": "activity-1", "payload": {"outcome": True}}
    validator.ingest_resolve_queue = [item]

    asyncio.run(validator.flush_ingest_resolutions())

    assert validator.ingest_resolve_queue == [item]


def test_flush_methods_are_noop_when_unconfigured():
    validator = _validator(None)
    validator.ingest_submit_queue = [{"fid": "x", "hotkey": "h", "payload": {}}]
    validator.ingest_resolve_queue = [{"hotkey": "h", "activity_id": "a", "payload": {}}]

    asyncio.run(validator.flush_ingest_submissions())
    asyncio.run(validator.flush_ingest_resolutions())

    # Untouched: no client means we must not mutate or attempt to process the
    # queues (defends against a client being cleared mid-run).
    assert len(validator.ingest_submit_queue) == 1
    assert len(validator.ingest_resolve_queue) == 1


# --------------------------------------------------------------- miner registration gating


def test_flush_ingest_submissions_registers_miner_before_first_activity():
    client = _FakeIngestClient()
    validator = _validator(client)
    validator.ingest_submit_queue = [
        {"fid": "fid-1", "uid": 0, "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    ]

    asyncio.run(validator.flush_ingest_submissions())

    assert len(client.upsert_calls) == 1
    assert client.upsert_calls[0]["hotkey"] == "hotkey-0"
    assert client.submit_calls == [("hotkey-0", {"eventType": "other"})]
    assert "hotkey-0" in validator.ingest_registered_hotkeys


def test_flush_ingest_submissions_skips_upsert_for_already_registered_hotkey():
    client = _FakeIngestClient()
    validator = _validator(client)
    validator.ingest_registered_hotkeys = {"hotkey-0"}
    validator.ingest_submit_queue = [
        {"fid": "fid-1", "uid": 0, "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    ]

    asyncio.run(validator.flush_ingest_submissions())

    assert client.upsert_calls == []
    assert client.submit_calls == [("hotkey-0", {"eventType": "other"})]


def test_flush_ingest_submissions_requeues_without_submitting_when_registration_fails():
    client = _FakeIngestClient()

    async def _failing_upsert(payload):
        raise httpx.ConnectError("boom")

    client.upsert_miner = _failing_upsert  # noqa: SLF001
    validator = _validator(client)
    item = {"fid": "fid-1", "uid": 0, "hotkey": "hotkey-0", "payload": {"eventType": "other"}}
    validator.ingest_submit_queue = [item]

    asyncio.run(validator.flush_ingest_submissions())

    assert validator.ingest_submit_queue == [item]
    assert client.submit_calls == []
    assert "hotkey-0" not in validator.ingest_registered_hotkeys


def test_sync_miner_registry_marks_hotkeys_registered():
    client = _FakeIngestClient()
    validator = _validator(client)

    asyncio.run(validator.sync_miner_registry())

    assert validator.ingest_registered_hotkeys == {"hotkey-0", "hotkey-1"}


# --------------------------------------------------------------- miner registry sync


def test_sync_miner_registry_is_noop_when_unconfigured():
    validator = _validator(None)

    asyncio.run(validator.sync_miner_registry())

    assert validator.last_miner_registry_sync_at == 0.0


def test_sync_miner_registry_builds_payload_and_omits_missing_trust():
    client = _FakeIngestClient()
    validator = _validator(client)

    asyncio.run(validator.sync_miner_registry())

    assert len(client.upsert_calls) == 2
    first = client.upsert_calls[0]
    assert first["uid"] == 0
    assert first["hotkey"] == "hotkey-0"
    assert first["netuid"] == 501
    assert first["coldkey"] == "cold-0"
    assert first["stakeTao"] == 10.0
    assert first["incentive"] == 0.1
    assert first["active"] is True
    assert "trust" not in first
    assert validator.last_miner_registry_sync_at > 0.0


def test_sync_miner_registry_respects_interval_gate(monkeypatch):
    monkeypatch.setenv("MASXAI_INGEST_MINER_SYNC_INTERVAL_SECONDS", "600")
    client = _FakeIngestClient()
    validator = _validator(client)
    validator.last_miner_registry_sync_at = __import__("time").time()

    asyncio.run(validator.sync_miner_registry())

    assert client.upsert_calls == []
