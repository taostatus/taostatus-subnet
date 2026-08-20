"""
masxai/scoring.py - LLM-key contribution scoring utilities.

Chain weight is driven solely by self.scores (see neurons/validator.py), an
EMA of llm_key_efficiency_score() below, computed from raw usage reports the
protocol backend reports back. Output quality can't be fairly judged here --
the protocol controls every prompt, and the models are third-party -- so this
deliberately scores only what a miner actually controls: reliability, speed,
real sustained call volume, and which model tier they bring.
"""

from masxai import constants as C


def ema_update(prev_score: float, new_reward: float, alpha: float = C.EMA_ALPHA) -> float:
    """Exponential moving average update of a miner's running score."""
    return (1.0 - alpha) * prev_score + alpha * new_reward


def llm_key_efficiency_score(
    *,
    success_count: int,
    failure_count: int,
    avg_latency_s: float | None,
    key_active: bool,
    model_tier_weight: float = 1.0,
    min_calls_for_scoring: int = C.LLM_KEY_MIN_CALLS_FOR_SCORING,
) -> float | None:
    """Turn one raw usage-report window into an efficiency reward in [0, 1].

    composite = reliability_weight*reliability + latency_weight*latency_score
              + volume_weight*volume_score
    score = composite * model_tier_weight

    model_tier_weight scales the whole composite so a high-tier key that's
    unreliable still scores low, and a lower-tier key that's perfectly
    reliable still scores respectably -- budget models aren't shut out, just
    capped below what a top-tier model can reach.

    Returns None (skip this window, not a penalty) when there isn't enough
    call volume to say anything meaningful yet -- a quiet key isn't a bad key.
    A key the protocol has marked inactive (exhausted/invalid/revoked) always
    scores 0.0 unconditionally, regardless of tier, so it decays out of
    self.scores via the normal EMA cadence rather than needing special-case
    removal logic.
    """
    if not key_active:
        return 0.0
    total = success_count + failure_count
    if total < min_calls_for_scoring:
        return None
    reliability = success_count / total
    if avg_latency_s is None:
        latency_score = 0.5  # neutral when the protocol didn't report latency
    else:
        latency_score = max(0.0, min(1.0, 1.0 - (avg_latency_s / C.LLM_KEY_LATENCY_CEILING_SECONDS)))
    volume_score = min(1.0, total / C.LLM_KEY_VOLUME_TARGET_CALLS)
    composite = (
        C.LLM_KEY_RELIABILITY_WEIGHT * reliability
        + C.LLM_KEY_LATENCY_WEIGHT * latency_score
        + C.LLM_KEY_VOLUME_WEIGHT * volume_score
    )
    tier = max(0.0, min(1.0, model_tier_weight))
    return composite * tier
