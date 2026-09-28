"""Test the security validator's round wiring with everything external faked:
no bittensor, no docker, no numpy.

Proves the chain query -> evaluate -> reward -> scores path: the validator asks
miners, evaluates each returned image, and scores each uid by the reward its
evaluation produced (with a None reward -- our fault -- left unscored).
"""

import asyncio
import types

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


def make_validator(responses, reward_by_ref):
    v = sv.SecurityValidator.__new__(sv.SecurityValidator)
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

    async def fake_dendrite(axons, synapse, deserialize, timeout):
        return responses
    v.dendrite = fake_dendrite

    # _evaluate now returns (reward, detail); reward None means "our fault"
    async def fake_evaluate(image_ref, miner_id):
        return (reward_by_ref[image_ref], "faked")
    v._evaluate = fake_evaluate

    v.captured = None
    def fake_apply(rewards):
        uids = list(rewards.keys())
        v.captured = ([rewards[u] for u in uids], uids)
    v._update_from_rewards = fake_apply

    return v


def resp(has_agent, image_ref=""):
    return types.SimpleNamespace(has_agent=has_agent, image_ref=image_ref)


def test_round_scores_each_miner_by_its_reward():
    responses = [resp(True, "ghcr.io/a:1"), resp(True, "ghcr.io/b:1")]
    rewards = {"ghcr.io/a:1": 1.0, "ghcr.io/b:1": 0.0}
    v = make_validator(responses, rewards)

    asyncio.run(v.security_round())

    scored = dict(zip(v.captured[1], v.captured[0]))
    assert scored == {1: 1.0, 2: 0.0}


def test_declining_miner_is_not_scored():
    responses = [resp(True, "ghcr.io/a:1"), resp(False)]
    v = make_validator(responses, {"ghcr.io/a:1": 1.0})
    asyncio.run(v.security_round())
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 1.0}


def test_our_fault_reward_is_not_scored():
    """A None reward (docker/orchestration failure) is left unscored, not zeroed."""
    responses = [resp(True, "ghcr.io/a:1"), resp(True, "ghcr.io/b:1")]
    rewards = {"ghcr.io/a:1": 1.0, "ghcr.io/b:1": None}
    v = make_validator(responses, rewards)
    asyncio.run(v.security_round())
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 1.0}   # uid2 skipped


def test_partial_score_is_scored():
    responses = [resp(True, "ghcr.io/a:1")]
    v = make_validator(responses, {"ghcr.io/a:1": 0.5})
    asyncio.run(v.security_round())
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 0.5}


def test_no_answers_scores_nothing():
    responses = [resp(None), resp(None)]
    v = make_validator(responses, {})
    asyncio.run(v.security_round())
    assert v.captured is None
