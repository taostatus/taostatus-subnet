"""Validator-side emission-from-usage scoring (Phase 3)."""

import asyncio
import types

import neurons.security_validator as sv


class _FakeUsageClient:
    def __init__(self, rows):
        self.rows = rows
        self.since = "unset"

    async def get_confirmed_usage(self, since=None):
        self.since = since
        return self.rows


def _validator(client, hotkeys, *, target=10, window=7 * 24 * 3600):
    v = sv.SecurityValidator.__new__(sv.SecurityValidator)
    v._marketplace = client
    v._usage_target_audits = target
    v._usage_window_s = window
    v.metagraph = types.SimpleNamespace(hotkeys=list(hotkeys))
    return v


def test_usage_scoring_maps_hotkeys_and_scores_volume_x_quality():
    rows = [
        {"agent_digest": "HK_A", "confirmed_count": 10, "avg_score": 0.9},
        {"agent_digest": "HK_B", "confirmed_count": 5, "avg_score": 0.8},
        {"agent_digest": "HK_GONE", "confirmed_count": 3, "avg_score": 1.0},  # not in metagraph
    ]
    client = _FakeUsageClient(rows)
    v = _validator(client, ["HK_A", "HK_B", "HK_C"])
    out = asyncio.run(v._recompute_scores_from_usage(now=1_000_000.0))
    # HK_A -> uid0 (10/10 * 0.9 = 0.9); HK_B -> uid1 (5/10 * 0.8 = 0.4);
    # HK_GONE skipped (no uid); HK_C (uid2) has no usage -> absent.
    assert out == {0: 0.9, 1: 0.4}
    assert client.since is not None and client.since != "unset"   # windowed


def test_unconfirmed_or_unscored_rows_earn_zero():
    rows = [
        {"agent_digest": "HK_A", "confirmed_count": 0, "avg_score": 1.0},    # no audits
        {"agent_digest": "HK_B", "confirmed_count": 5, "avg_score": None},   # unscored
    ]
    v = _validator(_FakeUsageClient(rows), ["HK_A", "HK_B"])
    out = asyncio.run(v._recompute_scores_from_usage(now=1000.0))
    assert out == {0: 0.0, 1: 0.0}


def test_poll_failure_is_fail_closed():
    class _Boom:
        async def get_confirmed_usage(self, since=None):
            raise RuntimeError("backend down")

    v = _validator(_Boom(), ["HK_A"])
    out = asyncio.run(v._recompute_scores_from_usage(now=1000.0))
    assert out == {}          # no weight change this round, never a crash


def test_no_client_returns_empty():
    v = _validator(None, ["HK_A"])
    out = asyncio.run(v._recompute_scores_from_usage(now=1000.0))
    assert out == {}
