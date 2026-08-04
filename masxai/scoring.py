"""
masxai/scoring.py - forecast scoring utilities.

The validator scores structured forecasts with the weighted formula from the
Phase 1 product spec:

Final Score = 50% Brier Skill + 20% Confidence Calibration
            + 20% Consistency + 10% Timeliness

The original Brier helpers stay available for probability-only tests and legacy
miners. Phase 1 uses probability as the primary score input for structured
forecasts, with a baseline gate so neutral 0.5 answers do not earn composite
reward.
"""

from masxai import constants as C


def clamp_prob(p: float) -> float:
    """Clamp a probability into [PROB_CLAMP_LO, PROB_CLAMP_HI]."""
    return max(C.PROB_CLAMP_LO, min(C.PROB_CLAMP_HI, p))


def clamp_confidence(confidence: float) -> float:
    """Clamp confidence into [0, 1]."""
    return max(C.CONFIDENCE_CLAMP_LO, min(C.CONFIDENCE_CLAMP_HI, confidence))


def brier_score(probability: float, outcome: bool) -> float:
    """(probability − outcome)^2, with probability clamped first."""
    p = clamp_prob(probability)
    return (p - float(outcome)) ** 2


def reward_from_brier(brier: float) -> float:
    """Convert a Brier score [0,1] into a reward [0,1] (higher = better)."""
    return max(0.0, 1.0 - brier)


def brier_skill(probability: float, outcome: bool, baseline_probability: float = C.NEUTRAL_PROB) -> float:
    """Brier skill versus a neutral/climatology baseline, clamped to [0, 1]."""
    baseline = brier_score(baseline_probability, outcome)
    if baseline <= 0.0:
        return 0.0
    skill = 1.0 - (brier_score(probability, outcome) / baseline)
    return max(0.0, min(1.0, skill))


def score_response(probability, outcome: bool) -> float:
    """
    Full reward for one resolved forecast.
    `probability` may be None if the miner didn't answer → assigned NO_ANSWER_BRIER.
    """
    if probability is None:
        return reward_from_brier(C.NO_ANSWER_BRIER)
    return reward_from_brier(brier_score(probability, outcome))


def ema_update(prev_score: float, new_reward: float, alpha: float = C.EMA_ALPHA) -> float:
    """Exponential moving average update of a miner's running score."""
    return (1.0 - alpha) * prev_score + alpha * new_reward


def calibration_score(prediction: bool, confidence: float, outcome: bool) -> float:
    """
    Reward confidence calibration for one binary forecast.

    A correct 0.90-confidence forecast scores 0.90. An incorrect 0.90-confidence
    forecast scores 0.10. Low confidence limits both upside and downside.
    """
    correct = prediction is outcome
    c = clamp_confidence(confidence)
    return c if correct else 1.0 - c


def timeliness_score(submitted_at: float, issued_at: float, resolve_at: float) -> float:
    """Score earlier answers higher, with zero credit at/after resolution."""
    if submitted_at <= issued_at:
        return 1.0
    horizon = max(1.0, resolve_at - issued_at)
    return max(0.0, min(1.0, 1.0 - ((submitted_at - issued_at) / horizon)))


def score_structured_forecast(
    prediction,
    confidence,
    outcome: bool,
    probability=None,
    previous_score: float = 0.5,
    submitted_at: float = 0.0,
    issued_at: float = 0.0,
    resolve_at: float = 1.0,
    baseline_gate: bool = C.BASELINE_COMPOSITE_GATE,
) -> float:
    """Return the Phase-1 weighted reward for one resolved structured forecast."""
    if probability is None and prediction is not None and confidence is not None:
        probability = float(confidence) if bool(prediction) else 1.0 - float(confidence)
    if probability is None or prediction is None or confidence is None:
        return 0.0

    pred = bool(prediction)
    acc = brier_skill(float(probability), outcome)
    if baseline_gate and acc <= 0.0:
        return 0.0
    cal = calibration_score(pred, float(confidence), outcome)
    consistency = clamp_confidence(float(previous_score))
    timely = timeliness_score(float(submitted_at), float(issued_at), float(resolve_at))

    return (
        C.ACCURACY_WEIGHT * acc
        + C.CALIBRATION_WEIGHT * cal
        + C.CONSISTENCY_WEIGHT * consistency
        + C.TIMELINESS_WEIGHT * timely
    )
