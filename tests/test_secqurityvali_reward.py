"""Tests for the verdict -> reward mapping that feeds Bittensor weights.

Pure and stdlib-only. The one rule that matters: a validator-fault verdict is
never scored against a miner.
"""

from secqurityVali.models import RejectReason, Stage, accept, reject
from secqurityVali.reward import (
    REWARD_FAIL,
    REWARD_PASS,
    reward_for_verdict,
    rewards_for_round,
)


def _accepted():
    return accept("miner-A", "ghcr.io/org/agent:1", agent_digest="d")


def _rejected(reason=RejectReason.DRY_RUN_NONZERO_EXIT, stage=Stage.DRY_RUN):
    return reject("miner-B", "ghcr.io/org/bad:1", stage, reason)


def test_accepted_earns_full_reward():
    assert reward_for_verdict(_accepted()) == REWARD_PASS


def test_rejected_on_merit_earns_zero():
    assert reward_for_verdict(_rejected()) == REWARD_FAIL


def test_not_a_docker_image_earns_zero():
    v = _rejected(RejectReason.NOT_A_DOCKER_IMAGE, Stage.STRUCTURE)
    assert reward_for_verdict(v) == REWARD_FAIL


def test_duplicate_agent_earns_zero():
    v = _rejected(RejectReason.DUPLICATE_AGENT, Stage.INSPECT)
    assert reward_for_verdict(v) == REWARD_FAIL


def test_docker_unavailable_is_not_scored():
    """Our daemon being down must never record a zero against a miner."""
    v = _rejected(RejectReason.DOCKER_UNAVAILABLE, Stage.LOAD)
    assert reward_for_verdict(v) is None


def test_internal_error_is_not_scored():
    v = _rejected(RejectReason.INTERNAL_ERROR, Stage.INSPECT)
    assert reward_for_verdict(v) is None


def test_round_drops_validator_faults_and_keeps_the_rest():
    results = {
        1: _accepted(),
        2: _rejected(),
        3: _rejected(RejectReason.DOCKER_UNAVAILABLE, Stage.LOAD),
        4: _rejected(RejectReason.NOT_A_DOCKER_IMAGE, Stage.STRUCTURE),
    }
    rewards, skipped = rewards_for_round(results)

    assert rewards == {1: REWARD_PASS, 2: REWARD_FAIL, 4: REWARD_FAIL}
    assert skipped == [3]          # the daemon-down one, retryable


def test_empty_round():
    rewards, skipped = rewards_for_round({})
    assert rewards == {} and skipped == []


# --- reward_for_job (the graded successor) ------------------------------

import types
from secqurityVali.reward import reward_for_job


def _job(*, error=None, safe=True, task_score=None):
    task = types.SimpleNamespace(score=task_score) if task_score is not None else None
    return types.SimpleNamespace(error=error, safe=safe, task=task)


def test_job_reward_is_the_task_score_when_safe():
    assert reward_for_job(_job(safe=True, task_score=1.0)) == 1.0
    assert reward_for_job(_job(safe=True, task_score=0.5)) == 0.5


def test_job_unsafe_scores_zero_even_with_a_task():
    assert reward_for_job(_job(safe=False, task_score=1.0)) == 0.0


def test_job_malformed_findings_scores_zero():
    assert reward_for_job(_job(safe=True, task_score=None)) == 0.0


def test_job_orchestration_error_is_not_scored():
    assert reward_for_job(_job(error="docker exploded", safe=True, task_score=1.0)) is None


# --- efficiency fold (capability x efficiency) --------------------------
import types as _t  # noqa: E402

from secqurityVali.reward import _efficiency_factor  # noqa: E402


def _ejob(score, requests, *, safe=True, error=None):
    return _t.SimpleNamespace(task=_t.SimpleNamespace(score=score), safe=safe,
                              error=error, request_count=requests)


def test_efficiency_rewards_surgical_over_bruteforce():
    lean = reward_for_job(_ejob(1.0, 50))      # well under target
    brute = reward_for_job(_ejob(1.0, 4000))   # well over target
    assert lean == 1.0 and brute < lean        # same capability, surgical wins
    assert 0.6 <= brute <= 0.75                 # scaled toward the floor, not zero


def test_efficiency_does_not_rescue_a_failed_run():
    assert reward_for_job(_ejob(0.0, 50)) == 0.0          # no capability -> 0 regardless
    assert reward_for_job(_ejob(1.0, 50, safe=False)) == 0.0   # safety veto still wins
    assert reward_for_job(_ejob(1.0, 50, error="docker")) is None


def test_efficiency_factor_bounds():
    assert _efficiency_factor(0) == 1.0                   # no requests -> no penalty
    assert _efficiency_factor(1) == 1.0                   # <= target -> full
    assert abs(_efficiency_factor(10**9) - 0.6) < 0.01                 # heavy waste -> floor
