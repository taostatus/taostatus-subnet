"""Test the security validator's round wiring with everything external faked:
no bittensor, no docker, no numpy.

Proves the chain query -> evaluate -> reward -> scores path: the validator asks
miners, evaluates each returned image, and scores each uid by the reward its
evaluation produced (with a None reward -- our fault -- left unscored).
"""

import asyncio
import tempfile
import types

import neurons.security_validator as sv
from secqurityVali.category_scores import CategoryScores


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
    # keypair state the ask carries; a real validator sets these in __init__.
    v._pubkey_b64 = "test-pubkey-b64"
    v._pubkey_id = "testpubid"
    # per-category capability matrix (single active category here, so the
    # aggregate equals the run's raw score -- first observation seeds the cell).
    v._active_categories = ("sqli",)
    v._cat_scores = CategoryScores(alpha=0.5)
    v._cat_scores_path = tempfile.mktemp(suffix=".json")
    v._freshness_s = 1e9         # effectively fresh forever for these tests
    # background-round state (a real validator sets these in __init__)
    v._round_task = None
    v._round_budget_s = 1e9      # effectively unbounded for tests
    v._forward_pace_s = 0.0

    async def fake_dendrite(axons, synapse, deserialize, timeout):
        return responses
    v.dendrite = fake_dendrite

    # _evaluate returns (reward, detail, category); reward None means "our fault"
    async def fake_evaluate(image_ref, miner_id):
        return (reward_by_ref[image_ref], "faked", "sqli")
    v._evaluate = fake_evaluate

    v.captured = None
    def fake_apply(rewards):
        uids = list(rewards.keys())
        v.captured = ([rewards[u] for u in uids], uids)
    v._update_from_rewards = fake_apply

    return v


def resp(has_agent, image_ref=""):
    return types.SimpleNamespace(has_agent=has_agent, image_ref=image_ref)


def resp_blob(has_agent, blob_url="", ciphertext_sha256="sha"):
    """A v2 encrypted-blob response (no plaintext image_ref)."""
    return types.SimpleNamespace(
        has_agent=has_agent,
        blob_url=blob_url,
        ciphertext_sha256=ciphertext_sha256,
        image_ref="",
    )


def test_encrypted_blob_path_is_scored():
    # A response carrying a blob_url routes to _evaluate_blob, not _evaluate.
    responses = [resp_blob(True, "http://miner-1/agent.enc")]
    v = make_validator(responses, {})

    called = {}
    async def fake_blob(blob_url, cipher_sha, miner_id):
        called["args"] = (blob_url, cipher_sha, miner_id)
        return (0.8, "faked-blob", "sqli")
    v._evaluate_blob = fake_blob

    asyncio.run(v.security_round())

    assert called["args"] == ("http://miner-1/agent.enc", "sha", "miner-1")
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 0.8}


def test_round_scores_each_miner_by_its_reward():
    responses = [resp(True, "ghcr.io/a:1"), resp(True, "ghcr.io/b:1")]
    rewards = {"ghcr.io/a:1": 1.0, "ghcr.io/b:1": 0.0}
    v = make_validator(responses, rewards)

    asyncio.run(v.security_round())

    scored = dict(zip(v.captured[1], v.captured[0]))
    assert scored == {1: 1.0, 2: 0.0}


def test_score_is_aggregate_across_active_categories():
    # With two active categories and only sqli solved, the score is the mean
    # across both (sqli=1.0, xss untested=0) -> 0.5. This is what stops a
    # one-trick agent from looking like an all-rounder.
    responses = [resp(True, "ghcr.io/a:1")]
    v = make_validator(responses, {"ghcr.io/a:1": 1.0})
    v._active_categories = ("sqli", "xss")
    asyncio.run(v.security_round())
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 0.5}


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


# --- F3: evaluation runs off the weight-set path -----------------------

def test_idle_miner_score_decays_to_zero():
    """F4: a miner scored in a past round but no longer producing fresh evidence
    has its score recomputed to 0 once its category cell goes stale -- it does
    not keep earning forever."""
    responses = [resp(None), resp(None)]        # nobody answers this round
    v = make_validator(responses, {})
    v._cat_scores.update("miner-1", "sqli", 1.0, now=0.0)  # an OLD solve (t=0)
    v._freshness_s = 100.0                        # 100s window; now() >> 100 -> stale
    asyncio.run(v.security_round())
    assert dict(zip(v.captured[1], v.captured[0])) == {1: 0.0}


def test_forward_does_not_block_on_a_slow_round():
    """forward() must return promptly and run the round in the background, so a
    slow evaluation never delays the base class's weight-setting (vtrust)."""
    v = make_validator([], {})
    v._round_task = None
    v._forward_pace_s = 0.0
    events = []

    async def slow_round():
        events.append("start")
        await asyncio.sleep(0.5)
        events.append("end")
    v.security_round = slow_round

    async def drive():
        await v.forward()                  # returns promptly; round still in flight
        assert v._round_task is not None
        assert not v._round_task.done()    # forward did NOT wait for the round
        assert events == ["start"]         # started, not finished
        await v._round_task                # let the background round finish
        assert events == ["start", "end"]
    asyncio.run(drive())


def test_forward_does_not_start_overlapping_rounds():
    """While a round is still running, forward() must not start a second one."""
    v = make_validator([], {})
    v._round_task = None
    v._forward_pace_s = 0.0
    calls = []

    async def slow_round():
        calls.append(1)
        await asyncio.sleep(0.5)
    v.security_round = slow_round

    async def drive():
        await v.forward()
        first = v._round_task
        await v.forward()                  # round still running -> reuse, no new task
        assert v._round_task is first
        assert len(calls) == 1
        await v._round_task
    asyncio.run(drive())
