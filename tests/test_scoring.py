"""
tests/test_scoring.py — verify LLM-key contribution scoring math.
Run:  pytest tests/test_scoring.py -v
"""

import math

from masxai import constants as C
from masxai.scoring import (
    ema_update,
    has_fatal_error_category,
    llm_key_efficiency_score,
    sanitize_latency_ms,
    sanitize_quality_score,
)


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
    # history and top-tier model -- the validator also kills that key
    # (see _kill_hotkey_key) so its rows stop earning immediately.
    assert llm_key_efficiency_score(
        success_count=100, failure_count=0, avg_latency_s=0.1, key_active=False,
        model_tier_weight=1.0,
    ) == 0.0


def _composite(
    reliability: float, latency_score: float, volume_score: float, quality: float = 0.5,
) -> float:
    # quality defaults to 0.5 -- the neutral value llm_key_efficiency_score()
    # substitutes whenever quality_score isn't passed (mirrors missing latency).
    return (
        C.LLM_KEY_RELIABILITY_WEIGHT * reliability
        + C.LLM_KEY_QUALITY_WEIGHT * quality
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


def test_llm_key_efficiency_volume_counts_only_successes():
    # A failed call is not delivered capacity: 10 successes score the same
    # volume whether or not failures are stacked alongside them -- failures
    # must never pad the volume axis. Compare at identical reliability by
    # checking the volume term in isolation: 10/0 vs 40/0 differ only in
    # success volume, while 10 successes + 10 failures must have the same
    # volume term as 10 successes alone (only reliability differs).
    ten_clean = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
    )
    ten_plus_failures = llm_key_efficiency_score(
        success_count=10, failure_count=10, avg_latency_s=0.0, key_active=True,
    )
    # reliability drops 1.0 -> 0.5; the volume term (10 successes) is unchanged.
    expected_drop = C.LLM_KEY_RELIABILITY_WEIGHT * (1.0 - 0.5)
    assert math.isclose(ten_clean - ten_plus_failures, expected_drop, abs_tol=1e-9)


def test_llm_key_efficiency_volume_capped_at_target():
    # Volume beyond the target doesn't keep adding reward -- capped at 1.0.
    # Perfect on every axis, including an explicit top quality_score, so the
    # composite is genuinely 1.0 (quality omitted would default to a neutral
    # 0.5, not "perfect").
    at_target = llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True, quality_score=1.0,
    )
    way_over_target = llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS * 10, failure_count=0, avg_latency_s=0.0,
        key_active=True, quality_score=1.0,
    )
    assert math.isclose(at_target, way_over_target, abs_tol=1e-9)
    assert math.isclose(at_target, 1.0, abs_tol=1e-9)  # perfect on every axis


def test_llm_key_efficiency_model_tier_weight_scales_composite():
    kwargs = dict(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True, quality_score=1.0,
    )
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
    kwargs = dict(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True, quality_score=1.0,
    )
    over_one = llm_key_efficiency_score(**kwargs, model_tier_weight=5.0)
    negative = llm_key_efficiency_score(**kwargs, model_tier_weight=-1.0)

    assert math.isclose(over_one, 1.0, abs_tol=1e-9)
    assert math.isclose(negative, 0.0, abs_tol=1e-9)


# --- hard floors -----------------------------------------------------------

def test_llm_key_efficiency_reliability_below_floor_scores_zero():
    # A majority-failing window means the key isn't working: no neutral
    # quality/latency credit, no volume credit, no tier rescue -- 0.0.
    assert llm_key_efficiency_score(
        success_count=2, failure_count=8, avg_latency_s=0.0, key_active=True,
        quality_score=1.0, model_tier_weight=1.0,
    ) == 0.0


def test_llm_key_efficiency_all_failures_scores_zero():
    # The original additive composite paid up to ~0.4 for a key failing
    # every single call (neutral defaults + volume credit). Never again.
    assert llm_key_efficiency_score(
        success_count=0, failure_count=C.LLM_KEY_VOLUME_TARGET_CALLS,
        avg_latency_s=0.0, key_active=True,
    ) == 0.0


def test_llm_key_efficiency_reliability_at_floor_still_scores():
    # The floor is strict: exactly at it, the window still earns its
    # (appropriately mediocre) composite.
    at_floor = llm_key_efficiency_score(
        success_count=5, failure_count=5, avg_latency_s=0.0, key_active=True,
    )
    assert at_floor is not None and at_floor > 0.0


def test_llm_key_efficiency_measured_low_quality_scores_zero():
    # Confirmed low-quality output (e.g. fabricated/ungrounded replies as
    # graded by the calling agent) earns nothing, even on a perfectly
    # reliable, fast, top-tier key.
    assert llm_key_efficiency_score(
        success_count=C.LLM_KEY_VOLUME_TARGET_CALLS, failure_count=0, avg_latency_s=0.0,
        key_active=True, quality_score=0.1, model_tier_weight=1.0,
        quality_call_count=C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED,
    ) == 0.0


def test_llm_key_efficiency_quality_floor_needs_enough_graded_calls():
    # One self-graded bad reply in an otherwise healthy window is signal for
    # the quality axis, not grounds to zero the whole key: below the graded
    # -call minimum the low reading scales the composite instead of gating it.
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        quality_score=0.1, quality_call_count=1,
    )
    assert math.isclose(result, _composite(1.0, 1.0, volume_score, quality=0.1), abs_tol=1e-9)


def test_llm_key_efficiency_unmeasured_quality_never_trips_the_floor():
    # None means "not graded", which stays neutral -- the floor only acts on
    # a measured reading.
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        quality_score=None, quality_call_count=0,
    )
    assert result is not None and result > 0.0


# --- fatal error categories --------------------------------------------------

def test_has_fatal_error_category_matches_backend_and_agent_vocabularies():
    assert has_fatal_error_category({"invalid_key": 1})
    assert has_fatal_error_category({"no_funds_or_budget": 2})
    assert has_fatal_error_category({"AuthenticationError": 1})  # agent exception class name
    assert has_fatal_error_category({"rate_limit": 3, "INVALID_KEY": 1})  # mixed, case-insensitive


def test_has_fatal_error_category_ignores_transient_and_empty():
    assert not has_fatal_error_category(None)
    assert not has_fatal_error_category({})
    assert not has_fatal_error_category({"rate_limit": 5})
    assert not has_fatal_error_category({"timeout": 1, "provider_outage": 2})
    assert not has_fatal_error_category({"HTTPStatusError": 1})  # ambiguous -> reliability's job


# --- quality_score --------------------------------------------------------

def test_llm_key_efficiency_quality_score_scales_composite():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    high_quality = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        quality_score=1.0,
    )
    mediocre_quality = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        quality_score=0.6,  # above the hard floor, so it scales rather than gates
    )
    assert math.isclose(high_quality, _composite(1.0, 1.0, volume_score, quality=1.0), abs_tol=1e-9)
    assert math.isclose(mediocre_quality, _composite(1.0, 1.0, volume_score, quality=0.6), abs_tol=1e-9)
    assert mediocre_quality < high_quality


def test_llm_key_efficiency_missing_quality_is_neutral():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        quality_score=None,
    )
    assert math.isclose(result, _composite(1.0, 1.0, volume_score, quality=0.5), abs_tol=1e-9)


# --- malformed-input hardening ---------------------------------------------

def test_llm_key_efficiency_nan_latency_treated_as_neutral():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=float("nan"), key_active=True,
    )
    assert math.isclose(result, _composite(1.0, 0.5, volume_score), abs_tol=1e-9)


def test_llm_key_efficiency_inf_latency_treated_as_neutral():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=float("inf"), key_active=True,
    )
    assert math.isclose(result, _composite(1.0, 0.5, volume_score), abs_tol=1e-9)


def test_llm_key_efficiency_negative_latency_treated_as_neutral():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    result = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=-5.0, key_active=True,
    )
    assert math.isclose(result, _composite(1.0, 0.5, volume_score), abs_tol=1e-9)


def test_llm_key_efficiency_negative_counts_return_none():
    assert llm_key_efficiency_score(
        success_count=-1, failure_count=5, avg_latency_s=0.0, key_active=True,
    ) is None
    assert llm_key_efficiency_score(
        success_count=5, failure_count=-1, avg_latency_s=0.0, key_active=True,
    ) is None


def test_llm_key_efficiency_malformed_model_tier_weight_falls_back_to_default():
    volume_score = 10 / C.LLM_KEY_VOLUME_TARGET_CALLS
    expected = _composite(1.0, 1.0, volume_score) * C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT
    nan_tier = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        model_tier_weight=float("nan"),
    )
    inf_tier = llm_key_efficiency_score(
        success_count=10, failure_count=0, avg_latency_s=0.0, key_active=True,
        model_tier_weight=float("inf"),
    )
    assert math.isclose(nan_tier, expected, abs_tol=1e-9)
    assert math.isclose(inf_tier, expected, abs_tol=1e-9)


def test_llm_key_efficiency_never_returns_nan_or_inf():
    adversarial_latency = [None, 0.0, float("nan"), float("inf"), float("-inf"), -5.0]
    adversarial_quality = [None, 0.0, 1.0, float("nan"), float("inf"), -5.0, 5.0]
    adversarial_tier = [1.0, 0.5, float("nan"), float("inf"), float("-inf"), -1.0, 5.0]
    adversarial_counts = [(10, 0), (0, 10), (-1, 10), (10, -1)]

    for latency in adversarial_latency:
        for quality in adversarial_quality:
            for tier in adversarial_tier:
                for success, failure in adversarial_counts:
                    result = llm_key_efficiency_score(
                        success_count=success, failure_count=failure,
                        avg_latency_s=latency, key_active=True,
                        quality_score=quality, model_tier_weight=tier,
                    )
                    assert result is None or (
                        isinstance(result, float)
                        and not math.isnan(result)
                        and not math.isinf(result)
                    )


def test_sanitize_latency_ms_passthrough_and_none():
    assert sanitize_latency_ms(None) is None
    assert sanitize_latency_ms(100.0) == 100.0


def test_sanitize_latency_ms_rejects_malformed():
    assert sanitize_latency_ms(float("nan")) is None
    assert sanitize_latency_ms(float("inf")) is None
    assert sanitize_latency_ms(-1.0) is None


def test_sanitize_quality_score_passthrough_and_none():
    assert sanitize_quality_score(None) is None
    assert sanitize_quality_score(0.0) == 0.0
    assert sanitize_quality_score(1.0) == 1.0
    assert sanitize_quality_score(0.5) == 0.5


def test_sanitize_quality_score_rejects_malformed():
    assert sanitize_quality_score(float("nan")) is None
    assert sanitize_quality_score(float("inf")) is None
    assert sanitize_quality_score(-0.1) is None
    assert sanitize_quality_score(1.1) is None
