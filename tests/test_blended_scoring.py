"""Validator-side BLENDED scoring: benchmark base + confirmed-audit bonus.

score = (1 - w) * benchmark + w * confirmed-audit usage. The bonus is additive and
capped at w, so a benchmark-perfect miner with no audits tops out at (1 - w) and
real, replay-confirmed audits add the rest up to 1.0; a usage poll failure or a
miner with no audit row simply contributes a 0 bonus (fail-safe)."""

import asyncio
import types

import neurons.security_validator as sv
from secqurityVali.category_scores import CategoryScores


class _FakeUsageClient:
    def __init__(self, rows):
        self.rows = rows

    async def get_confirmed_usage(self, since=None):
        return self.rows


def _validator(client, hotkeys, cells, *, categories=("sqli", "cmdi"),
               w=0.05, target=10, window=7 * 24 * 3600):
    v = sv.SecurityValidator.__new__(sv.SecurityValidator)
    v._marketplace = client
    v._usage_target_audits = target
    v._usage_window_s = window
    v._audit_bonus_weight = w
    v._active_categories = list(categories)
    v._freshness_s = None
    v._cat_scores = CategoryScores(alpha=0.5, cells=cells)
    v.metagraph = types.SimpleNamespace(hotkeys=list(hotkeys))
    return v


def _perfect_cells(hotkey, categories=("sqli", "cmdi"), value=1.0):
    return {hotkey: {c: {"score": value, "updated_at": 0.0} for c in categories}}


def test_perfect_benchmark_no_audits_caps_at_one_minus_w():
    # All categories solved, no confirmed audits -> 0.95, not 1.0.
    v = _validator(_FakeUsageClient([]), ["HK_A"], _perfect_cells("HK_A"))
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert out[0] == 0.95


def test_perfect_benchmark_plus_full_audits_reaches_one():
    rows = [{"agent_digest": "HK_A", "confirmed_count": 10, "avg_score": 1.0}]  # usage 1.0
    v = _validator(_FakeUsageClient(rows), ["HK_A"], _perfect_cells("HK_A"))
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert out[0] == 1.0


def test_audit_bonus_is_additive_and_capped():
    # 0.5 usage adds exactly w * 0.5 = 0.025 on top of the 0.95 base.
    rows = [{"agent_digest": "HK_A", "confirmed_count": 5, "avg_score": 1.0}]  # 5/10 = 0.5
    v = _validator(_FakeUsageClient(rows), ["HK_A"], _perfect_cells("HK_A"))
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert abs(out[0] - (0.95 + 0.05 * 0.5)) < 1e-9


def test_poll_failure_falls_back_to_benchmark_base():
    class _Boom:
        async def get_confirmed_usage(self, since=None):
            raise RuntimeError("backend down")

    v = _validator(_Boom(), ["HK_A"], _perfect_cells("HK_A"))
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert out[0] == 0.95          # benchmark base kept, bonus 0, never a crash


def test_usage_without_benchmark_earns_only_the_bonus_term():
    # A miner with confirmed audits but no benchmark history: bench 0, bonus only.
    rows = [{"agent_digest": "HK_A", "confirmed_count": 10, "avg_score": 1.0}]
    v = _validator(_FakeUsageClient(rows), ["HK_A"], cells={})
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert out[0] == 0.05          # (1-w)*0 + w*1.0


def test_relative_split_among_non_audit_miners_is_preserved():
    # Two miners, no audits, benchmarks 1.0 and 0.5 -> both scaled by (1-w),
    # so their ratio (and thus proportional emission share) is unchanged.
    cells = {
        "HK_A": {c: {"score": 1.0, "updated_at": 0.0} for c in ("sqli", "cmdi")},
        "HK_B": {c: {"score": 0.5, "updated_at": 0.0} for c in ("sqli", "cmdi")},
    }
    v = _validator(_FakeUsageClient([]), ["HK_A", "HK_B"], cells)
    out = asyncio.run(v._recompute_scores_blended(now=1000.0))
    assert out[0] == 0.95 and out[1] == 0.475
    assert abs((out[0] / out[1]) - (1.0 / 0.5)) < 1e-9
