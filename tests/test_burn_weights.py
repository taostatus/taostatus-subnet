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
