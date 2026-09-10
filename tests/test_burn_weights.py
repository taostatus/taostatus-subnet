import numpy as np
import pytest

from template.base.validator import (
    BURN_PERCENTAGE,
    BURN_UID,
    _apply_burn_allocation,
)


def test_burn_allocation_reserves_burn_percentage():
    uids, weights = _apply_burn_allocation(
        current_uids=np.array([1, 2, BURN_UID, 4]),
        weight_uids=np.array([1, 2, BURN_UID, 4]),
        weights=np.array([0.2, 0.3, 0.1, 0.4], dtype=np.float32),
    )

    weight_by_uid = dict(zip(uids.tolist(), weights.tolist()))

    assert np.isclose(weights.sum(), 1.0)
    assert np.isclose(weight_by_uid[BURN_UID], BURN_PERCENTAGE)
    assert np.isclose(
        sum(weight for uid, weight in weight_by_uid.items() if uid != BURN_UID),
        1.0 - BURN_PERCENTAGE,
    )


def test_burn_allocation_appends_burn_uid_when_not_processed():
    uids, weights = _apply_burn_allocation(
        current_uids=np.array([1, 2, BURN_UID, 4]),
        weight_uids=np.array([1, 2, 4]),
        weights=np.array([0.2, 0.3, 0.5], dtype=np.float32),
    )

    weight_by_uid = dict(zip(uids.tolist(), weights.tolist()))

    assert BURN_UID in weight_by_uid
    assert np.isclose(weights.sum(), 1.0)
    assert np.isclose(weight_by_uid[BURN_UID], BURN_PERCENTAGE)


def test_burn_allocation_requires_burn_uid_in_current_uids():
    with pytest.raises(ValueError, match=f"BURN_UID {BURN_UID} is not present"):
        _apply_burn_allocation(
            current_uids=np.array([1, 2, 3]),
            weight_uids=np.array([1, 2, 3]),
            weights=np.array([0.2, 0.3, 0.5], dtype=np.float32),
        )


# ---------------------------------------------------------------------------
# "No utilization, no emission"
#
# This subnet's rule is that weight is earned only through confirmed, reported
# usage of a contributed key -- never by registering, and never by merely
# answering the key ask. The path that threatens that rule is the all-zero
# score vector: process_weights_for_netuid answers it with "No non-zero
# weights returning all ones", a uniform split that would pay every
# registered miner an equal share of the non-burn allocation.
#
# These pin the two halves: nothing earned burns everything, and a real
# earner is still paid normally.
# ---------------------------------------------------------------------------

def test_zero_scores_burn_the_whole_allocation():
    # What set_weights hands down when no miner has a confirmed score.
    uids, weights = _apply_burn_allocation(
        current_uids=np.array([1, 2, BURN_UID, 4]),
        weight_uids=np.array([1, 2, BURN_UID, 4]),
        weights=np.zeros(4, dtype=np.float32),
    )

    weight_by_uid = dict(zip(uids.tolist(), weights.tolist()))
    assert np.isclose(weight_by_uid[BURN_UID], 1.0), "everything must burn"
    assert all(
        np.isclose(w, 0.0) for uid, w in weight_by_uid.items() if uid != BURN_UID
    ), "no miner may earn without a confirmed usage score"


def test_a_uniform_split_would_have_paid_everyone():
    # The regression guard: this is what an all-ones vector (the fallback
    # this subnet must not reach) produces -- every registered miner paid
    # equally for doing nothing. Kept as a contrast to the test above.
    uids, weights = _apply_burn_allocation(
        current_uids=np.array([1, 2, BURN_UID, 4]),
        weight_uids=np.array([1, 2, BURN_UID, 4]),
        weights=np.ones(4, dtype=np.float32),
    )
    weight_by_uid = dict(zip(uids.tolist(), weights.tolist()))
    paid = [w for uid, w in weight_by_uid.items() if uid != BURN_UID and w > 0]
    assert len(paid) == 3, "the uniform fallback pays every registered miner"


def test_one_earner_is_still_paid_normally():
    # The rule cuts only the unearned case; a miner with a real score keeps
    # the full non-burn share.
    uids, weights = _apply_burn_allocation(
        current_uids=np.array([1, 2, BURN_UID, 4]),
        weight_uids=np.array([1, 2, BURN_UID, 4]),
        weights=np.array([0.0, 0.87, 0.0, 0.0], dtype=np.float32),
    )
    weight_by_uid = dict(zip(uids.tolist(), weights.tolist()))
    assert np.isclose(weight_by_uid[BURN_UID], BURN_PERCENTAGE)
    assert np.isclose(weight_by_uid[2], 1.0 - BURN_PERCENTAGE)
    assert np.isclose(weight_by_uid[1], 0.0)
    assert np.isclose(weight_by_uid[4], 0.0)
