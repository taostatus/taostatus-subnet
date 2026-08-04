"""
tests/test_scoring.py — verify v1 scoring math before any testnet run.
Run:  pytest tests/test_scoring.py -v
"""

import math

from masxai import constants as C
from masxai.scoring import (
    clamp_prob,
    clamp_confidence,
    brier_score,
    brier_skill,
    calibration_score,
    reward_from_brier,
    score_response,
    score_structured_forecast,
    ema_update,
)
from masxai.oracle import resolve_outcome


def test_clamp_bounds():
    assert clamp_prob(0.0) == C.PROB_CLAMP_LO
    assert clamp_prob(1.0) == C.PROB_CLAMP_HI
    assert clamp_prob(0.5) == 0.5
    assert clamp_confidence(-1.0) == 0.0
    assert clamp_confidence(2.0) == 1.0


def test_brier_confident_correct_is_low():
    # p=0.99, outcome True -> tiny Brier
    assert brier_score(0.99, True) < 0.001


def test_brier_confident_wrong_is_high():
    # p=0.99, outcome False -> near-max Brier
    assert brier_score(0.99, False) > 0.95


def test_coinflip_floor():
    # predicting 0.5 yields Brier 0.25 -> reward 0.75 regardless of outcome
    assert math.isclose(score_response(0.5, True), 0.75, abs_tol=1e-9)
    assert math.isclose(score_response(0.5, False), 0.75, abs_tol=1e-9)


def test_no_answer_penalized_to_floor():
    # None answer -> NO_ANSWER_BRIER -> reward 0.5
    assert math.isclose(score_response(None, True),
                        reward_from_brier(C.NO_ANSWER_BRIER), abs_tol=1e-9)


def test_proper_scoring_rewards_honesty():
    # A miner who is right and confident beats the coin-flip floor.
    confident_right = score_response(0.9, True)
    coinflip = score_response(0.5, True)
    assert confident_right > coinflip


def test_brier_skill_zeroes_coinflip_baseline():
    assert math.isclose(brier_skill(0.5, True), 0.0, abs_tol=1e-9)
    assert brier_skill(0.9, True) > 0.9


def test_ema_moves_toward_reward():
    s = 0.0
    for _ in range(50):
        s = ema_update(s, 1.0)
    assert s > 0.9  # converges upward toward sustained reward


def test_structured_score_matches_mvp_weights():
    reward = score_structured_forecast(
        prediction=True,
        confidence=0.9,
        probability=0.9,
        outcome=True,
        previous_score=0.5,
        submitted_at=10.0,
        issued_at=0.0,
        resolve_at=100.0,
    )
    expected = (
        C.ACCURACY_WEIGHT * brier_skill(0.9, True)
        + C.CALIBRATION_WEIGHT * 0.9
        + C.CONSISTENCY_WEIGHT * 0.5
        + C.TIMELINESS_WEIGHT * 0.9
    )
    assert math.isclose(reward, expected, abs_tol=1e-9)


def test_structured_coinflip_gets_zero_with_baseline_gate():
    assert score_structured_forecast(
        prediction=True,
        confidence=0.5,
        probability=0.5,
        outcome=True,
        previous_score=0.9,
        submitted_at=10.0,
        issued_at=0.0,
        resolve_at=100.0,
    ) == 0.0


def test_structured_no_answer_gets_zero():
    assert score_structured_forecast(
        prediction=None,
        confidence=None,
        probability=None,
        outcome=True,
        previous_score=0.9,
        submitted_at=10.0,
        issued_at=0.0,
        resolve_at=100.0,
    ) == 0.0


def test_calibration_penalizes_confident_wrong():
    assert math.isclose(calibration_score(True, 0.9, True), 0.9, abs_tol=1e-9)
    assert math.isclose(calibration_score(True, 0.9, False), 0.1, abs_tol=1e-9)


def test_resolve_outcome_up_and_down():
    assert resolve_outcome(reference_price=100.0, resolved_price=101.0) is True
    assert resolve_outcome(reference_price=100.0, resolved_price=99.0) is False
    assert resolve_outcome(reference_price=100.0, resolved_price=100.0) is True  # flat = up
