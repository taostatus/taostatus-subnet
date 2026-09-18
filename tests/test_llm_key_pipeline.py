"""tests/test_llm_key_pipeline.py — validator-side LLM-key orchestration.

Mirrors the fake-object conventions used elsewhere in tests/ (a minimal
_FakeAxon/_FakeMetagraph/_FakeWallet/dendrite, and a
Validator.__new__(Validator) factory that sets only the attributes each test
needs).
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import numpy as np
import pytest

from masxai import constants as C
from masxai.llm_key_client import (
    LLMKeyAllowedModel,
    LLMKeyPublicKey,
    LLMKeyRosterEntry,
    LLMKeySubmitKeyResult,
    LLMKeySubmitResult,
    LLMKeyUsageReport,
)
from masxai.protocol import LLMKeySynapse
from masxai.scoring import ema_update
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

    def __init__(self, keys=None):
        self.calls = []
        self._keys = keys  # override miner-hotkey-1's key batch

    async def __call__(self, axons, synapse, deserialize=False, timeout=0):
        self.calls.append([axon.hotkey for axon in axons])
        responses = []
        for axon in axons:
            resp = synapse.model_copy(deep=True)
            if axon.hotkey == "miner-hotkey-1":
                resp.has_key = True
                resp.keys = self._keys if self._keys is not None else [{
                    "slot": 0,
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "encrypted_key_blob": "ZmFrZS1jaXBoZXJ0ZXh0",
                    "blob_encoding": "nacl-sealedbox-v1",
                    "pubkey_id_used": synapse.protocol_pubkey_id,
                }]
            else:
                resp.has_key = False
            responses.append(resp)
        return responses


def _five_distinct_keys() -> list[dict]:
    """Five slot entries with distinct physical-key blobs, meeting
    LLM_KEY_MIN_KEYS_PER_HOTKEY -- slot 0 mirrors _FakeLLMKeyDendrite's
    single-key default (openai/gpt-4o-mini) so existing slot-0 assertions
    still hold."""
    providers = [
        ("openai", "gpt-4o-mini"),
        ("anthropic", "claude-3-haiku"),
        ("mistral", "mistral-small"),
        ("deepseek", "deepseek-chat"),
        ("openai", "gpt-4o"),
    ]
    return [
        {
            "slot": i,
            "provider": provider,
            "model": model,
            "encrypted_key_blob": f"ZmFrZS1jaXBoZXJ0ZXh0-{i}",
            "blob_encoding": "nacl-sealedbox-v1",
            "pubkey_id_used": "v1",
        }
        for i, (provider, model) in enumerate(providers)
    ]


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
        self._submit_result = submit_result or LLMKeySubmitResult(
            accepted=True, status="ACTIVE",
            results=[LLMKeySubmitKeyResult(
                slot=0, key_id=1, provider="openai", model="gpt-4o-mini",
                accepted=True, status="ACTIVE",
            )],
        )
        self._reports: list[LLMKeyUsageReport] = []
        self._next_since = None
        self._roster: list[LLMKeyRosterEntry] = []

    async def get_public_key(self) -> LLMKeyPublicKey:
        return LLMKeyPublicKey(pubkey_id="v1", pubkey_b64="ZmFrZS1wdWJrZXk=")

    async def get_allowed_models(self) -> list[LLMKeyAllowedModel]:
        return [LLMKeyAllowedModel(provider="openai", model="gpt-4o-mini")]

    async def submit_keys(self, **kwargs) -> LLMKeySubmitResult:
        self.submit_calls.append(kwargs)
        return self._submit_result

    def set_reports(self, reports: list[LLMKeyUsageReport], *, next_since: str):
        self._reports = reports
        self._next_since = next_since

    async def get_reports(self, *, since=None):
        return self._reports, self._next_since

    def set_roster(self, roster: list[LLMKeyRosterEntry]):
        self._roster = roster

    async def get_key_statuses(self) -> list[LLMKeyRosterEntry]:
        return self._roster


def _single_call_reports(
    hotkey: str,
    *,
    successes: int,
    failures: int,
    latency_ms: float = 100.0,
    quality: float | None = None,
    key_active: bool = True,
    created_at: str = "2026-08-19T00:00:00Z",
    key_id: int | None = 1,
    provider: str | None = "openai",
    model: str | None = "gpt-4o-mini",
) -> list[LLMKeyUsageReport]:
    """Realistic one-row-per-call reports, mirroring what the real protocol
    actually sends (report_outcome() appends exactly one row per call --
    success_count/failure_count are always 0 or 1, never pre-aggregated,
    each tagged with the key row that served it). A single inflated row
    (success_count=9 etc.) is NOT realistic -- using one here is what let
    the missing-aggregation bug through the test suite in the first place."""
    reports = []
    for _ in range(successes):
        reports.append(LLMKeyUsageReport(
            hotkey=hotkey, key_id=key_id, provider=provider, model=model,
            success_count=1, failure_count=0,
            avg_latency_ms=latency_ms, avg_quality_score=quality,
            key_active=key_active, created_at=created_at,
        ))
    for _ in range(failures):
        reports.append(LLMKeyUsageReport(
            hotkey=hotkey, key_id=key_id, provider=provider, model=model,
            success_count=0, failure_count=1,
            avg_latency_ms=latency_ms, avg_quality_score=quality,
            key_active=key_active, created_at=created_at,
        ))
    return reports


def _validator(client, dendrite) -> Validator:
    validator = Validator.__new__(Validator)
    validator.metagraph = _FakeMetagraph()
    validator.wallet = _FakeWallet()
    validator.dendrite = dendrite
    validator.llm_key_client = client
    validator.llm_key_hotkey_status = {}
    validator.llm_key_pending_calls = {}
    validator.last_llm_key_ask_at = 0.0
    validator.last_llm_key_report_poll_at = 0.0
    validator.last_llm_key_report_cursor = ""
    validator.llm_key_reports_empty_since = 0.0
    validator.scores = np.zeros(3, dtype=np.float32)
    validator.participation_scores = {}
    return validator


def test_submission_round_only_submits_for_miners_with_a_key():
    client = _FakeLLMKeyClient()
    dendrite = _FakeLLMKeyDendrite(keys=_five_distinct_keys())
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert len(client.submit_calls) == 1
    submitted = client.submit_calls[0]
    assert submitted["hotkey"] == "miner-hotkey-1"
    assert len(submitted["keys"]) == 5
    assert submitted["keys"][0]["slot"] == 0
    assert submitted["keys"][0]["provider"] == "openai"
    assert submitted["keys"][0]["model"] == "gpt-4o-mini"
    status = validator.llm_key_hotkey_status["miner-hotkey-1"]
    assert status["accepted"] is True
    assert status["keys"]["1"]["alive"] is True  # keyed by backend key_id
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


def test_submission_round_records_rejection_without_zeroing_an_existing_active_key_score():
    # A resubmission getting rejected must never punish a hotkey whose
    # existing, still-active key is earning reports elsewhere -- the
    # protocol never touches an existing row on a rejected resubmission
    # (see submit_key() in llm_keys.py), so scoring must not either.
    client = _FakeLLMKeyClient(
        submit_result=LLMKeySubmitResult(
            accepted=False, status="REJECTED", reason="existing_key_in_use"
        )
    )
    dendrite = _FakeLLMKeyDendrite(keys=_five_distinct_keys())
    validator = _validator(client, dendrite)
    validator.scores[1] = 0.8

    asyncio.run(validator.llm_key_submission_round())

    assert validator.scores[1] == 0.8
    assert validator.llm_key_hotkey_status["miner-hotkey-1"]["accepted"] is False


def test_submission_round_rejection_is_a_noop_for_a_hotkey_with_no_prior_score():
    client = _FakeLLMKeyClient(
        submit_result=LLMKeySubmitResult(accepted=False, status="REJECTED", reason="model_not_allowed")
    )
    dendrite = _FakeLLMKeyDendrite(keys=_five_distinct_keys())
    validator = _validator(client, dendrite)

    asyncio.run(validator.llm_key_submission_round())

    assert validator.scores[1] == 0.0
    assert validator.llm_key_hotkey_status["miner-hotkey-1"]["accepted"] is False


def test_report_poll_round_updates_scores_for_known_hotkeys():
    client = _FakeLLMKeyClient()
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=C.LLM_KEY_VOLUME_TARGET_CALLS, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert validator.llm_key_hotkey_status["miner-hotkey-1"]["key_active"] is True
    assert validator.last_llm_key_report_cursor == "2026-08-19T00:00:00Z"
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls  # flushed after scoring


def test_report_poll_round_rewards_top_tier_model_more_than_default_tier():
    # Two hotkeys, identical usage history, different models -- the tier
    # weight now comes from each usage ROW's own provider/model (verified by
    # the backend at preflight), not from a submission-time lookup.
    client = _FakeLLMKeyClient()
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=C.LLM_KEY_VOLUME_TARGET_CALLS, failures=0,
            key_id=1, provider="openai", model="gpt-4o",           # tier 1.0
        )
        + _single_call_reports(
            "miner-hotkey-2", successes=C.LLM_KEY_VOLUME_TARGET_CALLS, failures=0,
            key_id=2, provider="deepseek", model="deepseek-chat",  # tier 0.5
        ),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > validator.scores[2] > 0.0


def test_report_poll_round_blends_tier_per_call_across_a_mixed_fleet():
    # A hotkey serving traffic on a gpt-4o key AND a gpt-4o-mini key gets a
    # per-call weighted blend of the two tiers -- more usable than either
    # extreme, and stacked cheap keys can never borrow a top-tier multiplier.
    def _scored(reports) -> float:
        client = _FakeLLMKeyClient()
        client.set_reports(reports, next_since="2026-08-19T00:00:00Z")
        validator = _validator(client, _FakeLLMKeyDendrite())
        asyncio.run(validator.llm_key_report_poll_round())
        return float(validator.scores[1])

    n = C.LLM_KEY_VOLUME_TARGET_CALLS
    top_only = _scored(_single_call_reports(
        "miner-hotkey-1", successes=n, failures=0, key_id=1, provider="openai", model="gpt-4o",
    ))
    budget_only = _scored(_single_call_reports(
        "miner-hotkey-1", successes=n, failures=0, key_id=2, provider="openai", model="gpt-4o-mini",
    ))
    mixed = _scored(
        _single_call_reports(
            "miner-hotkey-1", successes=n // 2, failures=0,
            key_id=1, provider="openai", model="gpt-4o",
        )
        + _single_call_reports(
            "miner-hotkey-1", successes=n // 2, failures=0,
            key_id=2, provider="openai", model="gpt-4o-mini",
        )
    )
    assert budget_only < mixed < top_only


def test_report_poll_round_does_not_score_below_threshold_even_across_single_call_rows():
    # This is the regression test for the bug that made the whole reward
    # path inert: the protocol reports one row per call, and a report row's
    # own success_count+failure_count is always 1 -- scoring per-row instead
    # of aggregating meant min_calls_for_scoring could never be crossed.
    client = _FakeLLMKeyClient()
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=C.LLM_KEY_MIN_CALLS_FOR_SCORING - 1, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0
    pending = validator.llm_key_pending_calls["miner-hotkey-1"]["keys"]["1"]
    assert pending["success_count"] == C.LLM_KEY_MIN_CALLS_FOR_SCORING - 1
    assert pending["failure_count"] == 0


def test_report_poll_round_scores_once_aggregated_calls_cross_threshold_within_one_poll():
    client = _FakeLLMKeyClient()
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=C.LLM_KEY_MIN_CALLS_FOR_SCORING, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_accumulates_pending_calls_across_multiple_polls():
    # The core regression test for the actual fix: low-traffic calls spread
    # across separate polls must still add up, not reset each cycle.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())

    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=2, failures=0),
        next_since="2026-08-19T00:00:01Z",
    )
    asyncio.run(validator.llm_key_report_poll_round())
    assert validator.scores[1] == 0.0
    assert validator.llm_key_pending_calls["miner-hotkey-1"]["keys"]["1"]["success_count"] == 2

    validator.last_llm_key_report_poll_at = 0.0  # bypass the poll-interval throttle
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=3, failures=0),
        next_since="2026-08-19T00:00:02Z",
    )
    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_key_active_false_hard_zeroes_and_clears_pending():
    # A report row marking the key inactive is conclusive -- emission stops
    # NOW (score straight to 0.0), not over many EMA decay steps.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.5  # pretend it had a score already
    validator.llm_key_pending_calls["miner-hotkey-1"] = {
        "keys": {"1": {
            "success_count": 3, "failure_count": 0,
            "latency_ms_weighted_sum": 0.0, "latency_weighted_count": 0,
            "quality_weighted_sum": 0.0, "quality_weighted_count": 0,
            "tier": 1.0,
        }},
        "first_seen_at": 0.0, "last_seen_at": 0.0,
    }
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=0, failures=1, key_active=False),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_fatal_error_category_hard_zeroes_immediately():
    # A single row whose error_categories says the provider rejected the key
    # itself (bad credentials / no budget) zeroes the score on the spot --
    # no call-volume floor, no waiting for the protocol's health check to
    # notice (it can lag or be disabled entirely, leaving the key ACTIVE).
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.7
    validator.llm_key_pending_calls["miner-hotkey-1"] = {
        "keys": {"1": {
            "success_count": 4, "failure_count": 0,
            "latency_ms_weighted_sum": 0.0, "latency_weighted_count": 0,
            "quality_weighted_sum": 0.0, "quality_weighted_count": 0,
            "tier": 1.0,
        }},
        "first_seen_at": 0.0, "last_seen_at": 0.0,
    }
    client.set_reports(
        [LLMKeyUsageReport(
            hotkey="miner-hotkey-1", key_id=1, provider="openai", model="gpt-4o-mini",
            success_count=0, failure_count=1,
            avg_latency_ms=100.0, error_categories={"invalid_key": 1},
            key_active=True, created_at="2026-08-19T00:00:00Z",
        )],
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_transient_error_category_folds_normally():
    # rate_limit / timeout are the reliability axis's job, never a kill switch.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.7
    client.set_reports(
        [LLMKeyUsageReport(
            hotkey="miner-hotkey-1", key_id=1, provider="openai", model="gpt-4o-mini",
            success_count=0, failure_count=1,
            avg_latency_ms=100.0, error_categories={"rate_limit": 1},
            key_active=True, created_at="2026-08-19T00:00:00Z",
        )],
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == pytest.approx(0.7)  # below volume floor: accumulated, not scored
    assert validator.llm_key_pending_calls["miner-hotkey-1"]["keys"]["1"]["failure_count"] == 1


def _seed_two_key_hotkey(validator, *, pending_calls_1=0, pending_calls_2=0):
    """A hotkey with two tracked keys (backend ids 1 and 2), optionally with
    pending traffic split between them."""
    validator.llm_key_hotkey_status["miner-hotkey-1"] = {
        "uid": 1,
        "keys": {
            "1": {"slot": 0, "provider": "openai", "model": "gpt-4o", "alive": True},
            "2": {"slot": 1, "provider": "openai", "model": "gpt-4o", "alive": True},
        },
    }
    if pending_calls_1 or pending_calls_2:
        keys = {}
        for sub_key, calls in (("1", pending_calls_1), ("2", pending_calls_2)):
            if calls:
                keys[sub_key] = {
                    "success_count": calls, "failure_count": 0,
                    "latency_ms_weighted_sum": 100.0 * calls, "latency_weighted_count": calls,
                    "quality_weighted_sum": 0.0, "quality_weighted_count": 0,
                    "tier": 1.0,
                }
        now = time.time()
        validator.llm_key_pending_calls["miner-hotkey-1"] = {
            "keys": keys, "first_seen_at": now, "last_seen_at": now,
        }


def test_killing_one_key_cuts_only_its_traffic_share():
    # A dead key on a multi-key hotkey costs exactly its recent traffic
    # share; the sibling key's earnings survive and its pending rows stay.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    _seed_two_key_hotkey(validator, pending_calls_1=1, pending_calls_2=3)
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=0, failures=1, key_active=False,
            key_id=1, provider="openai", model="gpt-4o",
        ),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    # dead key's share: (1 pending + 1 just-reported... the inactive row is
    # never folded, so share = 1/4 of tracked traffic) -> 0.8 * (1 - 0.25)
    assert validator.scores[1] == pytest.approx(0.6)
    key_states = validator.llm_key_hotkey_status["miner-hotkey-1"]["keys"]
    assert key_states["1"]["alive"] is False
    assert key_states["2"]["alive"] is True
    assert "1" not in validator.llm_key_pending_calls["miner-hotkey-1"]["keys"]
    assert "2" in validator.llm_key_pending_calls["miner-hotkey-1"]["keys"]


def test_killing_the_last_live_key_hard_zeroes_the_hotkey():
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    _seed_two_key_hotkey(validator)
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=0, failures=1, key_active=False,
            key_id=1, provider="openai", model="gpt-4o",
        )
        + _single_call_reports(
            "miner-hotkey-1", successes=0, failures=1, key_active=False,
            key_id=2, provider="openai", model="gpt-4o",
        ),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0


def test_roster_kill_is_idempotent_across_polls():
    # The roster re-reports DEAD forever; the share must be deducted once.
    client = _FakeLLMKeyClient()
    client.set_roster([LLMKeyRosterEntry(
        hotkey="miner-hotkey-1", key_id=1, slot=0,
        provider="openai", model="gpt-4o", status="DEAD",
    )])
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    _seed_two_key_hotkey(validator)

    asyncio.run(validator._poll_llm_key_roster())
    after_first = float(validator.scores[1])
    asyncio.run(validator._poll_llm_key_roster())

    assert 0.0 < after_first < 0.8  # one share cut (no traffic data -> equal-split fallback)
    assert float(validator.scores[1]) == pytest.approx(after_first)  # second poll: no-op


def test_junk_key_is_excluded_without_nuking_the_fleet():
    # One all-failures key hiding inside an otherwise healthy fleet is
    # killed by the per-key gate at flush; the fleet still scores on its
    # good traffic instead of hard-zeroing.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=0, failures=C.LLM_KEY_MIN_CALLS_FOR_SCORING,
            key_id=1, provider="openai", model="gpt-4o",
        )
        + _single_call_reports(
            "miner-hotkey-1", successes=45, failures=0,
            key_id=2, provider="openai", model="gpt-4o",
        ),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0  # fleet survived on the healthy key
    key_states = validator.llm_key_hotkey_status["miner-hotkey-1"]["keys"]
    assert key_states["1"]["alive"] is False
    assert key_states["2"].get("alive", True) is True


def test_load_state_migrates_old_flat_pending_shape(tmp_path, monkeypatch):
    # A validator restarting across the multi-key upgrade keeps a hotkey's
    # partial progress: the old flat accumulator becomes a "legacy" sub-key.
    state_file = tmp_path / "state.json"
    monkeypatch.setenv(C.VALIDATOR_STATE_FILE_ENV, str(state_file))
    state_file.write_text(json.dumps({
        "participation_scores": {},
        "llm_key_hotkey_status": {"miner-hotkey-1": {"uid": 1, "provider": "openai", "model": "gpt-4o"}},
        "llm_key_pending_calls": {"miner-hotkey-1": {
            "success_count": 3, "failure_count": 1,
            "latency_ms_weighted_sum": 400.0, "latency_weighted_count": 4,
            "quality_weighted_sum": 0.0, "quality_weighted_count": 0,
            "first_seen_at": 100.0, "last_seen_at": 200.0,
        }},
    }))
    validator = _validator(_FakeLLMKeyClient(), _FakeLLMKeyDendrite())

    validator.load_masxai_state()

    migrated = validator.llm_key_pending_calls["miner-hotkey-1"]
    assert migrated["keys"]["legacy"]["success_count"] == 3
    assert migrated["keys"]["legacy"]["failure_count"] == 1
    assert migrated["keys"]["legacy"]["tier"] is None  # resolved at flush via legacy lookup
    assert migrated["first_seen_at"] == 100.0


def test_validate_miner_keys_caps_and_sanitizes_the_relay():
    validator = _validator(None, _FakeLLMKeyDendrite())

    def key(slot, **overrides):
        entry = {
            "slot": slot, "provider": "openai", "model": "gpt-4o",
            "encrypted_key_blob": "blob", "blob_encoding": "nacl-sealedbox-v1",
            "pubkey_id_used": "v1",
        }
        entry.update(overrides)
        return entry

    # more than the cap -> extras ignored
    too_many = [key(slot) for slot in range(C.LLM_KEY_MAX_KEYS_PER_HOTKEY)] + [key(0)]
    assert len(validator._validate_miner_keys(1, too_many)) == C.LLM_KEY_MAX_KEYS_PER_HOTKEY
    # malformed entries skipped: bad slot, duplicate slot, missing fields, non-dict
    assert validator._validate_miner_keys(1, [
        key(99), key(-1), key("0"), key(0, provider=""), key(0, encrypted_key_blob=""),
        "not-a-dict", key(1), key(1),
    ]) == [key(1)]
    assert validator._validate_miner_keys(1, None) == []


def test_report_poll_round_majority_failing_window_hard_zeroes():
    # Once a full window (>= the call-volume floor) shows the key failing
    # most of its calls, the miner stops earning immediately -- the old
    # behavior EMA-blended in a still-substantial composite built from
    # neutral quality/latency defaults plus volume credit.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=0, failures=C.LLM_KEY_MIN_CALLS_FOR_SCORING,
        ),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_low_quality_window_hard_zeroes():
    # Confirmed low-quality output (enough graded calls below the quality
    # floor) cuts emission immediately, even though every call "succeeded".
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    client.set_reports(
        _single_call_reports(
            "miner-hotkey-1", successes=C.LLM_KEY_MIN_CALLS_FOR_SCORING, failures=0,
            quality=0.1,  # e.g. Chain-Agent's fabricated-evidence grade
        ),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_single_bad_graded_call_does_not_nuke_healthy_window():
    # One self-graded bad reply among an otherwise clean window drags the
    # quality axis but must not zero the key: the quality floor needs
    # LLM_KEY_QUALITY_FLOOR_MIN_GRADED graded calls to act.
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    good_calls = C.LLM_KEY_MIN_CALLS_FOR_SCORING - 1
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=good_calls, failures=0, quality=None)
        + _single_call_reports("miner-hotkey-1", successes=1, failures=0, quality=0.1),
        next_since="2026-08-19T00:00:00Z",
    )

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0


def test_report_poll_round_pending_window_force_flushes_after_max_age():
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=1, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    asyncio.run(validator.llm_key_report_poll_round())
    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" in validator.llm_key_pending_calls

    # Age the pending window past the max, then re-poll with no new reports
    # -- the force-flush must still fire even with nothing new to fold in.
    validator.llm_key_pending_calls["miner-hotkey-1"]["first_seen_at"] -= (
        C.LLM_KEY_PENDING_WINDOW_MAX_SECONDS + 1
    )
    validator.last_llm_key_report_poll_at = 0.0
    client.set_reports([], next_since=None)

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls


def test_report_poll_round_pending_calls_survive_state_save_and_load(tmp_path, monkeypatch):
    monkeypatch.setenv(C.VALIDATOR_STATE_FILE_ENV, str(tmp_path / "state.json"))
    client = _FakeLLMKeyClient()
    validator = _validator(client, _FakeLLMKeyDendrite())
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=2, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    asyncio.run(validator.llm_key_report_poll_round())
    pending_before = dict(validator.llm_key_pending_calls["miner-hotkey-1"])

    validator.save_masxai_state()

    reloaded = _validator(client, _FakeLLMKeyDendrite())
    reloaded.load_masxai_state()

    pending_after = reloaded.llm_key_pending_calls["miner-hotkey-1"]
    assert pending_after["keys"]["1"]["success_count"] == pending_before["keys"]["1"]["success_count"]
    assert pending_after["keys"]["1"]["failure_count"] == pending_before["keys"]["1"]["failure_count"]


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
        _single_call_reports("deregistered-hotkey", successes=9, failures=1),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert np.array_equal(validator.scores, np.zeros(3, dtype=np.float32))
    # cursor still advances so the unscoreable reports aren't refetched forever
    assert validator.last_llm_key_report_cursor == "2026-08-19T00:00:00Z"


def test_report_poll_round_is_noop_when_client_is_none():
    validator = _validator(None, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert np.array_equal(validator.scores, np.zeros(3, dtype=np.float32))
    assert validator.last_llm_key_report_poll_at == 0.0


# --- _prune_llm_key_hotkey_status -------------------------------------------

def test_prune_llm_key_hotkey_status_evicts_after_grace_period():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {"gone-hotkey": {"uid": 5, "_missing_since": 0.0}}
    validator.llm_key_pending_calls = {"gone-hotkey": {"success_count": 1}}

    validator._prune_llm_key_hotkey_status(C.LLM_KEY_HOTKEY_STATUS_EVICTION_GRACE_SECONDS + 1)

    assert "gone-hotkey" not in validator.llm_key_hotkey_status
    assert "gone-hotkey" not in validator.llm_key_pending_calls  # co-evicted


def test_prune_llm_key_hotkey_status_keeps_recently_missing_hotkey():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {"gone-hotkey": {"uid": 5, "_missing_since": 100.0}}

    validator._prune_llm_key_hotkey_status(100.0 + 60)  # well under the grace period

    assert "gone-hotkey" in validator.llm_key_hotkey_status


def test_prune_llm_key_hotkey_status_clears_missing_since_when_hotkey_reappears():
    validator = _validator(None, _FakeLLMKeyDendrite())
    # miner-hotkey-1 IS in _FakeMetagraph.hotkeys, so it's not actually "gone"
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1, "_missing_since": 50.0}}

    validator._prune_llm_key_hotkey_status(1000.0)

    assert "_missing_since" not in validator.llm_key_hotkey_status["miner-hotkey-1"]


# --- _decay_stale_llm_key_scores --------------------------------------------

def test_decay_stale_llm_key_scores_decays_frozen_score_toward_zero():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1, "last_report_at": 0.0}}

    validator._decay_stale_llm_key_scores(C.LLM_KEY_STALENESS_TIMEOUT_SECONDS + 1)

    expected = ema_update(0.8, 0.0, alpha=C.LLM_KEY_EMA_ALPHA)
    assert validator.scores[1] == pytest.approx(expected)
    assert validator.scores[1] < 0.8


def test_decay_stale_llm_key_scores_does_not_touch_fresh_hotkeys():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1, "last_report_at": 999.0}}

    validator._decay_stale_llm_key_scores(1000.0)  # only 1s stale, well under timeout

    assert validator.scores[1] == 0.8


def test_decay_stale_llm_key_scores_skips_zero_score_and_missing_last_report_at():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.0
    validator.scores[2] = 0.8
    validator.llm_key_hotkey_status = {
        "miner-hotkey-1": {"uid": 1, "last_report_at": 0.0},  # score already 0, no-op
        "miner-hotkey-2": {"uid": 2},  # no last_report_at at all, no-op
    }

    validator._decay_stale_llm_key_scores(C.LLM_KEY_STALENESS_TIMEOUT_SECONDS + 1)

    assert validator.scores[1] == 0.0
    assert validator.scores[2] == 0.8


# --- _poll_llm_key_roster ----------------------------------------------------

def test_poll_llm_key_roster_hard_zeroes_dead_key():
    # DEAD on the roster is the protocol's own confirmation -- the score
    # drops straight to zero, not one EMA step at a time, so a dead key
    # never draws emission for even one more epoch.
    client = _FakeLLMKeyClient()
    client.set_roster([LLMKeyRosterEntry(hotkey="miner-hotkey-1", status="DEAD")])
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1}}
    validator.llm_key_pending_calls["miner-hotkey-1"] = {"success_count": 2}

    asyncio.run(validator._poll_llm_key_roster())

    assert validator.scores[1] == 0.0
    assert "miner-hotkey-1" not in validator.llm_key_pending_calls  # moot once dead


def test_poll_llm_key_roster_hard_zeroes_revoked_key():
    client = _FakeLLMKeyClient()
    client.set_roster([LLMKeyRosterEntry(hotkey="miner-hotkey-1", status="REVOKED")])
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1}}

    asyncio.run(validator._poll_llm_key_roster())

    assert validator.scores[1] == 0.0


def test_poll_llm_key_roster_ignores_active_keys():
    client = _FakeLLMKeyClient()
    client.set_roster([LLMKeyRosterEntry(hotkey="miner-hotkey-1", status="ACTIVE")])
    validator = _validator(client, _FakeLLMKeyDendrite())
    validator.scores[1] = 0.8
    validator.llm_key_hotkey_status = {"miner-hotkey-1": {"uid": 1}}

    asyncio.run(validator._poll_llm_key_roster())

    assert validator.scores[1] == 0.8


def test_poll_llm_key_roster_is_noop_when_client_is_none():
    validator = _validator(None, _FakeLLMKeyDendrite())
    asyncio.run(validator._poll_llm_key_roster())  # must not raise


# --- weight blending ---------------------------------------------------------

def test_blended_weight_array_ignores_participation_entirely():
    # Weight is earned only through confirmed LLM-key efficiency (self.scores).
    # participation_scores is tracked for observability only and must never
    # leak into submitted weight, no matter how high it is.
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.participation_scores = {1: 0.6, 2: 0.9}
    validator.scores = np.zeros(3, dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.zeros(3, dtype=np.float32))


def _reported_usage_status(uid: int = 1, **overrides) -> dict:
    """A hotkey status entry in the shape the report poll leaves behind: the
    protocol has reported usage for this hotkey, on a live key. This is what
    makes a score payable (see Validator._has_llm_key_evidence)."""
    status = {
        "uid": uid,
        "last_report_at": time.time(),
        "key_active": True,
        "keys": {"1": {"alive": True, "provider": "openai", "model": "gpt-4o"}},
    }
    status.update(overrides)
    return status


def test_blended_weight_array_is_llm_key_efficiency_only():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.participation_scores = {1: 1.0}
    validator.llm_key_hotkey_status = {"miner-hotkey-1": _reported_usage_status()}
    validator.scores = np.array([0.0, 0.82, 0.0], dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.array([0.0, 0.82, 0.0], dtype=np.float32))


# --- only reported usage is payable -----------------------------------------
#
# A positive self.scores entry is earnings only if an LLM-key report put it
# there. The pre-LLM-key subnet persisted its forecasting accuracy EMA under
# the same "scores" key of the same state file, so an in-place upgrade would
# otherwise keep paying miners for work this subnet no longer measures.

def test_blended_weight_array_withholds_weight_from_scores_with_no_reports():
    validator = _validator(None, _FakeLLMKeyDendrite())
    # Inherited from a pre-LLM-key state file: a score, and nothing that says
    # the protocol ever reported usage for this hotkey.
    validator.scores = np.array([0.0, 0.82, 0.41], dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.zeros(3, dtype=np.float32))
    # Masking is submission-local: the EMA itself is untouched.
    assert validator.scores[1] == pytest.approx(0.82, abs=1e-6)


def test_blended_weight_array_withholds_weight_when_keys_are_on_file_but_unused():
    # Keys accepted, no usage reported yet -- a submission alone earns nothing.
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {
        "miner-hotkey-1": {"uid": 1, "accepted": True, "status": "ACTIVE"},
    }
    validator.scores = np.array([0.0, 0.82, 0.0], dtype=np.float32)

    assert np.array_equal(validator._blended_weight_array(), np.zeros(3, dtype=np.float32))


def test_blended_weight_array_withholds_weight_when_the_uid_changed_hands():
    # The score belongs to whoever held uid 1 before; the hotkey there now has
    # earned nothing (its own status entry still points at its old uid).
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {"miner-hotkey-1": _reported_usage_status(uid=2)}
    validator.scores = np.array([0.0, 0.82, 0.0], dtype=np.float32)

    assert np.array_equal(validator._blended_weight_array(), np.zeros(3, dtype=np.float32))


def test_blended_weight_array_withholds_weight_when_every_key_is_dead():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {
        "miner-hotkey-1": _reported_usage_status(
            keys={"1": {"alive": False}, "2": {"alive": False}},
        ),
    }
    validator.scores = np.array([0.0, 0.82, 0.0], dtype=np.float32)

    assert np.array_equal(validator._blended_weight_array(), np.zeros(3, dtype=np.float32))


def test_a_score_earned_from_real_reports_is_paid():
    # The other half of the rule: the gate must never stand between a miner
    # and weight it actually earned. A plain report poll leaves behind
    # everything _has_llm_key_evidence looks for.
    client = _FakeLLMKeyClient()
    client.set_reports(
        _single_call_reports("miner-hotkey-1", successes=C.LLM_KEY_VOLUME_TARGET_CALLS, failures=0),
        next_since="2026-08-19T00:00:00Z",
    )
    validator = _validator(client, _FakeLLMKeyDendrite())

    asyncio.run(validator.llm_key_report_poll_round())

    assert validator.scores[1] > 0.0
    assert validator._blended_weight_array()[1] == pytest.approx(
        float(validator.scores[1]), abs=1e-6
    )


def test_load_state_discards_pre_llm_key_scores(tmp_path, monkeypatch):
    # The exact shape the forecasting validator wrote: participation plus an
    # accuracy EMA under "scores", and no llm_key_hotkey_status at all.
    state_file = tmp_path / "state.json"
    monkeypatch.setenv(C.VALIDATOR_STATE_FILE_ENV, str(state_file))
    state_file.write_text(json.dumps({
        "participation_scores": {"1": 0.9, "2": 0.7},
        "scores": [0.0, 0.64, 0.31],
    }))
    validator = _validator(_FakeLLMKeyClient(), _FakeLLMKeyDendrite())

    validator.load_masxai_state()

    assert np.array_equal(validator.scores, np.zeros(3, dtype=np.float32))
    # Nothing is left behind for a later report row to unlock.
    assert np.array_equal(validator._blended_weight_array(), np.zeros(3, dtype=np.float32))


def test_load_state_keeps_scores_backed_by_reported_usage(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setenv(C.VALIDATOR_STATE_FILE_ENV, str(state_file))
    state_file.write_text(json.dumps({
        "llm_key_hotkey_status": {"miner-hotkey-1": _reported_usage_status()},
        "scores": [0.0, 0.64, 0.0],
    }))
    validator = _validator(_FakeLLMKeyClient(), _FakeLLMKeyDendrite())

    validator.load_masxai_state()

    assert validator.scores[1] == pytest.approx(0.64, abs=1e-6)
    assert validator._blended_weight_array()[1] == pytest.approx(0.64, abs=1e-6)


def test_blended_weight_array_is_nan_safe():
    validator = _validator(None, _FakeLLMKeyDendrite())
    validator.llm_key_hotkey_status = {"miner-hotkey-1": _reported_usage_status()}
    validator.scores = np.array([np.nan, 0.5, np.inf], dtype=np.float32)

    blended = validator._blended_weight_array()

    assert np.array_equal(blended, np.array([0.0, 0.5, 0.0], dtype=np.float32))
