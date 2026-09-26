"""Test the security validator's round wiring end to end, with everything
external faked: no bittensor, no docker, no numpy.

Proves the chain query -> pipeline -> reward -> scores path holds together:
the validator asks miners, evaluates the images they return, and scores each
uid correctly (including not scoring a validator-fault verdict).
"""

import asyncio
import types

from secqurityVali.models import RejectReason, Stage, accept, reject
import neurons.security_validator as sv


class FakeAxon:
    def __init__(self, serving=True):
        self.is_serving = serving


class FakeMetagraph:
    def __init__(self, hotkeys, serving):
        self.hotkeys = hotkeys
        self.axons = [FakeAxon(s) for s in serving]
        self.validator_permit = [False] * len(hotkeys)
        self.n = len(hotkeys)


def make_validator(responses, verdict_by_ref):
    """Build a SecurityValidator with base __init__ bypassed and its chain
    dependencies replaced by fakes."""
    v = sv.SecurityValidator.__new__(sv.SecurityValidator)

    # metagraph: uid0 = us, uid1/2 = miners serving axons
    v.metagraph = FakeMetagraph(
        hotkeys=["us-hotkey", "miner-1", "miner-2"],
        serving=[True, True, True],
    )
    v.wallet = types.SimpleNamespace(
        hotkey=types.SimpleNamespace(ss58_address="us-hotkey")
    )
    v.config = types.SimpleNamespace(netuid=501)
    v.last_security_round_at = 0.0
    v.db_path = ":memory:"

    # dendrite returns the canned responses, in uid order
    async def fake_dendrite(axons, synapse, deserialize, timeout):
        return responses
    v.dendrite = fake_dendrite

    # _evaluate returns a verdict chosen by image_ref, no docker involved
    async def fake_evaluate(image_ref, miner_id):
        return (1, verdict_by_ref[image_ref], 42)
    v._evaluate = fake_evaluate

    # capture the reward mapping instead of touching numpy / real scores
    v.captured = None
    def fake_apply(rewards):
        uids = list(rewards.keys())
        v.captured = ([rewards[u] for u in uids], uids)
    v._update_from_rewards = fake_apply

    return v


def resp(has_agent, image_ref=""):
    return types.SimpleNamespace(has_agent=has_agent, image_ref=image_ref)


def test_round_scores_each_miner_by_its_verdict():
    responses = [
        resp(True, "ghcr.io/a:1"),   # miner-1: will pass
        resp(True, "ghcr.io/b:1"),   # miner-2: will fail on merit
    ]
    verdicts = {
        "ghcr.io/a:1": accept("miner-1", "ghcr.io/a:1", agent_digest="d1"),
        "ghcr.io/b:1": reject("miner-2", "ghcr.io/b:1", Stage.DRY_RUN,
                              RejectReason.DRY_RUN_NONZERO_EXIT),
    }
    v = make_validator(responses, verdicts)

    asyncio.run(v.security_round())

    rewards, uids = v.captured
    scored = dict(zip(uids, rewards))
    assert scored == {1: 1.0, 2: 0.0}   # uid1 passed, uid2 failed


def test_declining_miner_is_not_scored():
    responses = [resp(True, "ghcr.io/a:1"), resp(False)]  # miner-2 declines
    verdicts = {"ghcr.io/a:1": accept("miner-1", "ghcr.io/a:1", agent_digest="d1")}
    v = make_validator(responses, verdicts)

    asyncio.run(v.security_round())

    rewards, uids = v.captured
    assert dict(zip(uids, rewards)) == {1: 1.0}   # only the answering miner


def test_validator_fault_verdict_is_not_scored():
    """A miner whose image failed because OUR docker was down is left
    unscored, not zeroed."""
    responses = [resp(True, "ghcr.io/a:1"), resp(True, "ghcr.io/b:1")]
    verdicts = {
        "ghcr.io/a:1": accept("miner-1", "ghcr.io/a:1", agent_digest="d1"),
        "ghcr.io/b:1": reject("miner-2", "ghcr.io/b:1", Stage.LOAD,
                              RejectReason.DOCKER_UNAVAILABLE),
    }
    v = make_validator(responses, verdicts)

    asyncio.run(v.security_round())

    rewards, uids = v.captured
    assert dict(zip(uids, rewards)) == {1: 1.0}   # uid2 skipped, not zeroed


def test_no_answers_scores_nothing():
    responses = [resp(None), resp(None)]   # both timed out
    v = make_validator(responses, {})
    asyncio.run(v.security_round())
    assert v.captured is None                # update_scores never called
