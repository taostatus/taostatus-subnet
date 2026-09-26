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
