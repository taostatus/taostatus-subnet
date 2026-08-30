"""
masxai/scoring.py - LLM-key contribution scoring utilities.

Chain weight is driven solely by self.scores (see neurons/validator.py), an
EMA of llm_key_efficiency_score() below, computed from raw usage reports the
protocol backend reports back. This scores reliability, per-call output
quality (self-graded by the calling agent -- see quality_score below),
speed, real sustained call volume, and which model tier a miner brings.
"""

import math

from masxai import constants as C


def ema_update(prev_score: float, new_reward: float, alpha: float = C.EMA_ALPHA) -> float:
    """Exponential moving average update of a miner's running score."""
    return (1.0 - alpha) * prev_score + alpha * new_reward


def sanitize_latency_ms(value: float | None) -> float | None:
    """None (not reported) and malformed (NaN, inf, negative) both collapse
    to None -- "no usable latency figure," handled identically downstream.
    Despite the name, the same NaN/inf/negative check is unit-agnostic --
    it's reused as-is on avg_latency_s (seconds) inside
    llm_key_efficiency_score() below, not just on raw millisecond figures."""
    if value is None or math.isnan(value) or math.isinf(value) or value < 0:
        return None
    return value


def sanitize_quality_score(value: float | None) -> float | None:
    """Same idea as sanitize_latency_ms(), plus a [0, 1] range check --
    quality_score is a bounded score, not just a non-negative measurement."""
    if value is None or math.isnan(value) or math.isinf(value) or not (0.0 <= value <= 1.0):
        return None
    return value


def has_fatal_error_category(error_categories: dict | None) -> bool:
    """True if a usage-report row's error_categories marks the key itself as
    unusable at the provider (bad credentials, exhausted budget, permission
    block) rather than transiently failing (rate limit, timeout, outage).

    Matched case-insensitively against C.LLM_KEY_FATAL_ERROR_CATEGORIES,
    since two vocabularies land in this field: the protocol health check's
    lowercased status values and the raw exception class names agents
    report. A fatal category is the one per-call signal strong enough to
    zero a hotkey's score on its own -- the provider itself said the key
    doesn't work, no call-volume floor needed."""
    if not error_categories:
        return False
    return any(
        str(category).strip().lower() in C.LLM_KEY_FATAL_ERROR_CATEGORIES
        for category in error_categories
    )


def llm_key_efficiency_score(
    *,
    success_count: int,
    failure_count: int,
    avg_latency_s: float | None,
    key_active: bool,
    quality_score: float | None = None,
    model_tier_weight: float = 1.0,
    min_calls_for_scoring: int = C.LLM_KEY_MIN_CALLS_FOR_SCORING,
    quality_call_count: int | None = None,
    reliability_floor: float = C.LLM_KEY_RELIABILITY_HARD_FLOOR,
    quality_floor: float = C.LLM_KEY_QUALITY_HARD_FLOOR,
    quality_floor_min_graded: int = C.LLM_KEY_QUALITY_FLOOR_MIN_GRADED,
) -> float | None:
    """Turn one raw usage-report window into an efficiency reward in [0, 1].

    composite = reliability_weight*reliability + quality_weight*quality
              + latency_weight*latency_score + volume_weight*volume_score
    score = composite * model_tier_weight

    model_tier_weight scales the whole composite so a high-tier key that's
    unreliable still scores low, and a lower-tier key that's perfectly
    reliable still scores respectably -- budget models aren't shut out, just
    capped below what a top-tier model can reach.

    Two hard floors sit in front of the composite, because an additive blend
    on its own would let a key that isn't actually working keep collecting
    the neutral-default quality/latency terms:

    - reliability below reliability_floor (majority-failing window, strict
      <, so a window exactly at the floor still scores) -> 0.0. A key that
      fails most of its calls is not a working key, whatever its tier.
    - measured quality below quality_floor -> 0.0, but only once at least
      quality_floor_min_graded calls in the window actually carried a
      quality grade (quality_call_count; None means "unknown, assume
      enough") -- one self-graded bad reply must not zero a whole healthy
      window. Unmeasured quality stays neutral and never trips the floor.

    Volume counts only successful calls -- a failed call is not delivered
    capacity, so failures can't pad the volume axis.

    Returns None (skip this window, not a penalty) when there isn't enough
    call volume to say anything meaningful yet -- a quiet key isn't a bad
    key -- or when success_count/failure_count is malformed (negative):
    there's no meaningful neutral reliability figure the way there is for
    latency, so an untrustworthy count means "nothing to score," not "score
    zero."

    A key the protocol has marked inactive (exhausted/invalid/revoked) always
    scores 0.0 unconditionally, regardless of tier. Whether a 0.0 reward is
    EMA'd in or drops the score straight to zero is the caller's decision
    (see Validator._record_llm_key_score) -- this function just says what
    the window is worth.

    avg_latency_s and quality_score are both optional and independently
    sanitized (NaN/inf/out-of-range collapse to "not reported") -- a
    malformed reading in one never disqualifies the other, and either
    missing/unusable figure degrades to a neutral 0.5 rather than being
    treated as a penalty. This function never returns NaN or inf.
    """
    if not key_active:
        return 0.0
    if success_count < 0 or failure_count < 0:
        return None
    total = success_count + failure_count
    if total < min_calls_for_scoring:
        return None
    reliability = success_count / total

    if math.isnan(reliability_floor) or math.isinf(reliability_floor):
        reliability_floor = C.LLM_KEY_RELIABILITY_HARD_FLOOR
    if reliability < reliability_floor:
        return 0.0  # a key failing most of its calls isn't working -- earns nothing

    quality_score = sanitize_quality_score(quality_score)
    quality = 0.5 if quality_score is None else quality_score  # neutral when not measured

    if math.isnan(quality_floor) or math.isinf(quality_floor):
        quality_floor = C.LLM_KEY_QUALITY_HARD_FLOOR
    if (
        quality_score is not None
        and quality_score < quality_floor
        and (quality_call_count is None or quality_call_count >= quality_floor_min_graded)
    ):
        return 0.0  # confirmed low-quality output earns nothing, whatever the other axes say

    avg_latency_s = sanitize_latency_ms(avg_latency_s)
    if avg_latency_s is None:
        latency_score = 0.5  # neutral when latency is missing or unusable
    else:
        latency_score = max(0.0, min(1.0, 1.0 - (avg_latency_s / C.LLM_KEY_LATENCY_CEILING_SECONDS)))

    volume_score = min(1.0, success_count / C.LLM_KEY_VOLUME_TARGET_CALLS)

    composite = (
        C.LLM_KEY_RELIABILITY_WEIGHT * reliability
        + C.LLM_KEY_QUALITY_WEIGHT * quality
        + C.LLM_KEY_LATENCY_WEIGHT * latency_score
        + C.LLM_KEY_VOLUME_WEIGHT * volume_score
    )

    # Python's min/max are not reliably NaN-safe (order-dependent), so guard
    # explicitly before the clamp below rather than relying on it.
    if math.isnan(model_tier_weight) or math.isinf(model_tier_weight):
        model_tier_weight = C.LLM_KEY_MODEL_TIER_DEFAULT_WEIGHT
    tier = max(0.0, min(1.0, model_tier_weight))

    return composite * tier
