"""
tests/test_scoring.py — verify LLM-key contribution scoring math.
Run:  pytest tests/test_scoring.py -v
"""

import math

from masxai import constants as C
from masxai.scoring import ema_update, llm_key_efficiency_score


def test_ema_moves_toward_reward():
    s = 0.0
    for _ in range(50):
        s = ema_update(s, 1.0)
    assert s > 0.9  # converges upward toward sustained reward


def test_llm_key_efficiency_skips_below_min_volume():
    # A quiet key isn't a bad key: below the minimum call count, skip (None),
    # never penalize with a zero.
    assert llm_key_efficiency_score(
        success_count=0, failure_count=0, avg_latency_s=1.0, key_active=True,
    ) is None


def test_llm_key_efficiency_dead_key_always_zero():
    # An inactive key scores 0.0 unconditionally, even with a perfect success
    # history and top-tier model, so it decays out of self.scores via the
    # normal EMA cadence.
    assert llm_key_efficiency_score(
        success_count=100, failure_count=0, avg_latency_s=0.1, key_active=False,
        model_tier_weight=1.0,
    ) == 0.0


def _composite(reliability: float, latency_score: float, volume_score: float) -> float:
    return (
        C.LLM_KEY_RELIABILITY_WEIGHT * reliability
        + C.LLM_KEY_LATENCY_WEIGHT * latency_score
        + C.LLM_KEY_VOLUME_WEIGHT * volume_score
    )


def test_llm_key_efficiency_reliability_and_latency_blend():
    # 10 calls, target is 50, so volume_score = 10/50 = 0.2 for all three cases.
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS

    fast_reliable = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
    )
    assert math.isclose(fast_reliable, _composite(1.0, 1.0, volume_score), abs_tol=1e-9)

    slow_reliable = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=C.LLM_KEY_LATENCY_CEILING_SECONDS,
        key_active=True,
    )
    assert math.isclose(slow_reliable, _composite(1.0, 0.0, volume_score), abs_tol=1e-9)

    half_reliable = llm_key_efficiency_score(
        success_count=5, failure_count=5, avg_latency_s=0.0, key_active=True,
    )
    assert half_reliable < fast_reliable


def test_llm_key_efficiency_latency_clamped_beyond_ceiling():
    # Latency worse than the ceiling clamps to 0.0 latency_score, not negative.
    at_ceiling = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=C.LLM_KEY_LATENCY_CEILING_SECONDS,
        key_active=True,
    )
    way_over = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=C.LLM_KEY_LATENCY_CEILING_SECONDS * 10,
        key_active=True,
    )
    assert math.isclose(at_ceiling, way_over, abs_tol=1e-9)


def test_llm_key_efficiency_missing_latency_is_neutral():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    with_neutral_latency = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=None, key_active=True,
    )
    assert math.isclose(with_neutral_latency, _composite(1.0, 0.5, volume_score), abs_tol=1e-9)


def test_llm_key_efficiency_volume_scales_with_call_count():
    # Same perfect reliability/latency, but one key has served far more real
    # volume -- it should score higher, not identically, per the pipeline's
    # original intent of rewarding real sustained capacity.
    low_volume = llm_key_efficiency_score(
        success_count=C.LLM_KEY_MIN_CALLS_FOR_SCORING, failure_count=0, avg_latency_s=0.0,
        key_active=True,
    )
    high_volume = llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True,
    )
    assert high_volume > low_volume


def test_llm_key_efficiency_volume_capped_at_target():
    # Volume beyond the target doesn't keep adding reward -- capped at 1.0.
    at_target = llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True,
    )
    way_over_target = llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS * 10, failure_count=0, avg_latency_s=0.0,
        key_active=True,
    )
    assert math.isclose(at_target, way_over_target, abs_tol=1e-9)
    assert math.isclose(at_target, 1.0, abs_tol=1e-9)  # perfect on every axis


def test_llm_key_efficiency_model_tier_weight_scales_composite():
    kwargs = dict(success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0, key_active=True)
    top_tier = llm_key_efficiency_score(**kwargs, model_tier_weight=1.0)
    budget_tier = llm_key_efficiency_score(**kwargs, model_tier_weight=0.5)

    assert math.isclose(top_tier, 1.0, abs_tol=1e-9)
    assert math.isclose(budget_tier, 0.5, abs_tol=1e-9)
    assert budget_tier < top_tier


def test_llm_key_efficiency_model_tier_weight_never_saves_an_unreliable_key():
    # A perfect tier weight can't rescue a genuinely unreliable, slow, quiet key.
    unreliable_top_tier = llm_key_efficiency_score(
        success_count=1, failure_count=9, avg_latency_s=C.LLM_KEY_LATENCY_CEILING_SECONDS,
        key_active=True, model_tier_weight=1.0,
    )
    assert unreliable_top_tier < 0.2


def test_llm_key_efficiency_model_tier_weight_clamped_to_unit_range():
    kwargs = dict(success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0, key_active=True)
    over_one = llm_key_efficiency_score(**kwargs, model_tier_weight=5.0)
    negative = llm_key_efficiency_score(**kwargs, model_tier_weight=-1.0)

    assert math.isclose(over_one, 1.0, abs_tol=1e-9)
    assert math.isclose(negative, 0.0, abs_tol=1e-9)
