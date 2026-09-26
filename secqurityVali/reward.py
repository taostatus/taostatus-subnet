from __future__ import annotations

"""secqurityVali/reward.py - turn a Verdict into a validator reward.

The bridge between the submission pipeline (which produces a Verdict) and the
Bittensor weight machinery (which wants a number per miner). Pure and
stdlib-only, so the mapping is unit-tested here rather than discovered on a
live validator.

For this milestone the reward is binary: a submission that passed every check
earns 1.0, one that failed on its own merits earns 0.0. When the SQLi
evaluation loop lands, `reward_for_verdict` is where the graded
task_score.score (0.0-1.0) replaces the binary pass/fail -- the neuron above it
does not change.

The important distinction is the third case: a verdict that failed because the
*validator* broke (Docker down, internal error) is not a judgement about the
miner at all. It returns None -- "do not score this round" -- so a validator
outage never records a zero against a miner who did nothing wrong.
"""

from secqurityVali.models import Verdict

REWARD_PASS = 1.0
REWARD_FAIL = 0.0


def reward_for_verdict(verdict: Verdict) -> float | None:
    """Map one Verdict to a reward.

    Returns:
        1.0   the submission was accepted
        0.0   the submission was rejected on its own merits
        None  the run failed on our side (retryable) -- do not score
    """
    if verdict.validator_fault:
        return None
    return REWARD_PASS if verdict.accepted else REWARD_FAIL


def rewards_for_round(
    results: dict[int, Verdict],
) -> tuple[dict[int, float], list[int]]:
    """Map a round's {uid: verdict} to {uid: reward}, dropping the uids whose
    verdict was our own fault.

    Returns (rewards, skipped_uids) so the caller can log who was skipped and
    why rather than silently omitting them.
    """
    rewards: dict[int, float] = {}
    skipped: list[int] = []
    for uid, verdict in results.items():
        reward = reward_for_verdict(verdict)
        if reward is None:
            skipped.append(uid)
        else:
            rewards[uid] = reward
    return rewards, skipped
