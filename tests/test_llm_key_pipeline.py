"""tests/test_llm_key_pipeline.py — validator-side LLM-key orchestration.

Mirrors the fake-object conventions used elsewhere in tests/ (a minimal
_FakeAxon/_FakeMetagraph/_FakeWallet/dendrite, and a
Validator.__new__(Validator) factory that sets only the attributes each test
needs).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import numpy as np

from masxai import constants as C
from masxai.llm_key_client import LLMKeyAllowedModel, LLMKeyPublicKey, LLMKeySubmitResult, LLMKeyUsageReport
from masxai.protocol import LLMKeySynapse
from neurons.validator import Validator


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


class _FakeLLMKeyDendrite:
    """miner-hotkey-1 has a key to contribute, miner-hotkey-2 doesn't but
    still answers (has_key=False), simulating basic axon liveness."""

    def __init__(self):
        self.calls = []

    async def __call__(self, axons, synapse, deserialize=False, timeout=0):
        self.calls.append([axon.hotkey for axon in axons])
        responses = []
        for axon in axons:
            resp = synapse.model_copy(deep=True)
            if axon.hotkey == "miner-hotkey-1":
                resp.has_key = True
                resp.provider = "openai"
                resp.model = "gpt-4o-mini"
                resp.encrypted_key_blob = "ZmFrZS1jaXBoZXJ0ZXh0"
                resp.blob_encoding = "nacl-sealedbox-v1"
                resp.pubkey_id_used = synapse.protocol_pubkey_id
            else:
                resp.has_key = False
            responses.append(resp)
        return responses


class _FakeTimeoutDendrite:
    """Every miner times out: has_key stays None (never touched by forward())."""

    def __init__(self):
        self.calls = []

    async def __call__(self, axons, synapse, deserialize=False, timeout=0):
        self.calls.append([axon.hotkey for axon in axons])
        return [synapse.model_copy(deep=True) for _ in axons]


class _FakeLLMKeyClient:
    def __init__(self, *, submit_result=None):
        self.submit_calls = []
        self._submit_result = submit_result or LLMKeySubmitResult(accepted=True, status="ACTIVE")
        self._reports: list[LLMKeyUsageReport] = []
        self._next_since = None

    async def get_public_key(self) -> LLMKeyPublicKey:
        return LLMKeyPublicKey(pubkey_id="v1", pubkey_b64="ZmFrZS1wdWJrZXk=")

    async def get_allowed_models(self) -> list[LLMKeyAllowedModel]:
        return [LLMKeyAllowedModel(provider="openai", model="gpt-4o-mini")]

    async def submit_key(self, **kwargs) -> LLMKeySubmitResult:
        self.submit_calls.append(kwargs)
        return self._submit_result

    def set_reports(self, reports: list[LLMKeyUsageReport], *, next_since: str):
        self._reports = reports
        self._next_since = next_since

    async def get_reports(self, *, since=None):
        return self._reports, self._next_since


def _validator(client, dendrite) -> Validator:
    validator = Validator.__new__(Validator)
    validator.metagraph = _FakeMetagraph()
    validator.wallet = _FakeWallet()
    validator.dendrite = dendrite
    validator.llm_key_client = client
    validator.llm_key_hotkey_status = {}
    validator.last_llm_key_ask_at = 0.0
    validator.last_llm_key_report_poll_at = 0.0
    validator.last_llm_key_report_cursor = ""
    validator.scores = np.zeros(3, dtype=np.float32)
    validator.participation_scores = {}
    return validator


def test_submission_round_only_submits_for_miners_with_a_key():
    client = _FakeLLMKeyClient()
    dendrite = _FakeLLMKeyDendrite()
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert len(client.submit_calls) == 1
    submitted = client.submit_calls[0]
    assert submitted["hotkey"] == "miner-hotkey-1"
    assert submitted["provider"] == "openai"
    assert submitted["model"] == "gpt-4o-mini"
    assert validator.llm_key_hotkey_status["miner-hotkey-1"]["accepted"] is True
    assert "miner-hotkey-2" not in validator.llm_key_hotkey_status
    assert validator.last_llm_key_ask_at > 0.0


def test_submission_round_records_participation_for_every_miner_that_answered():
    # miner-hotkey-2 answered (has_key=False) but didn't contribute a key --
    # it should still get liveness credit for responding at all.
    client = _FakeLLMKeyClient()
    dendrite = _FakeLLMKeyDendrite()
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert 1 in validator.participation_scores
    assert 2 in validator.participation_scores
    assert validator.participation_scores[1] > 0.0
    assert validator.participation_scores[2] > 0.0


def test_submission_round_does_not_record_participation_for_timeouts():
    client = _FakeLLMKeyClient()
    dendrite = _FakeTimeoutDendrite()
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert validator.participation_scores == {}
    assert client.submit_calls == []


def test_submission_round_relays_the_dendrite_query_to_all_miners_not_self():
    client = _FakeLLMKeyClient()
    dendrite = _FakeLLMKeyDendrite()
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert len(dendrite.calls) == 1
    queried_hotkeys = dendrite.calls[0]
    assert "validator-hotkey" not in queried_hotkeys
    assert set(queried_hotkeys) == {"miner-hotkey-1", "miner-hotkey-2"}


def test_submission_round_is_noop_when_client_is_none():
    dendrite = _FakeLLMKeyDendrite()
    validator = _validator(None, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert dendrite.calls == []
    assert validator.last_llm_key_ask_at == 0.0


def test_report_poll_round_updates_scores_for_known_hotkeys():
    client = _FakeLLMKeyClient()
    client.set_reports(
        [
            LLMKeyUsageReport(
                hotkey="miner-hotkey-1",
                success_count=9,
                failure_count=1,
                avg_latency_ms=100.0,
                key_active=True,
                created_at="2026-08-19T00:00:00Z",
            ),
        ],
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert validator.llm_key_hotkey_status["miner-hotkey-1"]["key_active"] is True
    assert validator.last_llm_key_report_cursor == "2026-08-19T00:00:00Z"


def test_report_poll_round_rewards_top_tier_model_more_than_default_tier():
    # Two hotkeys, identical usage history, different contributed models --
    # tier weight is looked up locally from llm_key_hotkey_status (captured
    # at submission time), no protocol round-trip needed.
    client = _FakeLLMKeyClient()
    identical_report = dict(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_ms=0.0,
        key_active=True, created_at="2026-08-19T00:00:00Z",
    )
    client.set_reports(
        [
            LLMKeyUsageReport(hotkey="miner-hotkey-1", **identical_report),
            LLMKeyUsageReport(hotkey="miner-hotkey-2", **identical_report),
        ],
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {
        "miner-hotkey-1": {"provider": "openai", "model": "gpt-4o"},          # tier 1.0
        "miner-hotkey-2": {"provider": "deepseek", "model": "deepseek-chat"},  # tier 0.5
    }

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > validator.scores[2] > 0.0


def test_model_tier_weight_defaults_when_hotkey_unknown():
    validator = _validator(None, _FakeLLMKeyDendrite())
    assert validator._model_tier_weight("never-seen-hotkey") == C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT


def test_model_tier_weight_looks_up_known_provider_model():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {
        "miner-hotkey-1": {"provider": "openai", "model": "gpt-4o"},
    }
    assert validator._model_tier_weight("miner-hotkey-1") == C.LLM_KEY_MODEL_TIER_WEIGHTS["openai/gpt-4o"]


def test_report_poll_round_skips_unknown_hotkey_without_crashing():
    client = _FakeLLMKeyClient()
    client.set_reports(
        [
            LLMKeyUsageReport(
                hotkey="deregistered-hotkey",
                success_count=9,
                failure_count=1,
                key_active=True,
                created_at="2026-08-19T00:00:00Z",
            ),
        ],
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert np.array_equal(validator.scores, np.zeros(3, dtype=np.float32))
    # cursor still advances so the unscoreable report isn't refetched forever
    assert validator.last_llm_key_report_cursor == "2026-08-19T00:00:00Z"


def test_report_poll_round_is_noop_when_client_is_none():
    validator = _validator(None, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert np.array_equal(validator.scores, np.zeros(3, dtype=np.float32))
    assert validator.last_llm_key_report_poll_at == 0.0


def test_blended_weight_array_ignores_participation_entirely():
    # Weight is earned only through confirmed LLM-key efficiency (self.scores).
    # participation_scores is tracked for observability only and must never
    # leak into submitted weight, no matter how high it is.
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.participation_scores = {1: 0.6, 2: 0.9}
    validator.scores = np.zeros(3, dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.zeros(3, dtype=np.float32))


def test_blended_weight_array_is_llm_key_efficiency_only():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.participation_scores = {1: 1.0}
    validator.scores = np.array([0.0, 0.82, 0.0], dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.array([0.0, 0.82, 0.0], dtype=np.float32))


def test_blended_weight_array_is_nan_safe():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.scores = np.array([np.nan, 0.5, np.inf], dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.array([0.0, 0.5, 0.0], dtype=np.float32))
