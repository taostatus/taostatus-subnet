from __future__ import annotations

"""Normalize reliability profile scores and optionally submit chain weights."""

import logging
from typing import Sequence

from config import Settings
from masxai import constants as C
from models import MinerRegistration, ReliabilityProfile, utcnow


logger = logging.getLogger(__name__)
BURN_UID = C.BURN_UID
BURN_PERCENTAGE = C.BURN_PERCENTAGE


def normalize_weights(session_factory) -> list[tuple[int, float, float]]:
    with session_factory() as session:
        rows = (
            session.query(MinerRegistration, ReliabilityProfile)
            .join(ReliabilityProfile, ReliabilityProfile.miner_uid == MinerRegistration.uid)
            .filter(MinerRegistration.is_active.is_(True))
            .all()
        )
        total = sum(
            max(0.0, float(profile.base_score))
            for _miner, profile in rows
            if int(profile.valid_count or 0) > 0
        )
        results: list[tuple[int, float, float]] = []
        for miner, profile in rows:
            raw = (
                max(0.0, float(profile.base_score))
                if int(profile.valid_count or 0) > 0
                else 0.0
            )
            normalized = raw / total if total > 0 else 0.0
            profile.raw_weight = raw
            profile.normalized_weight = normalized
            profile.updated_at = utcnow()
            results.append((miner.uid, raw, normalized))
        session.commit()
        return sorted(results, key=lambda item: item[0])


def set_weights(settings: Settings, session_factory) -> list[tuple[int, float, float]]:
    weights = normalize_weights(session_factory)
    if settings.dry_run_weights:
        logger.info("DRY_RUN_WEIGHTS=true; normalized weights=%s", weights)
        return weights
    positive_weights = [
        (uid, norm) for uid, raw, norm in weights if raw > 0.0 and norm > 0.0
    ]
    if not positive_weights:
        logger.info(
            "skipping chain weight submission: no miner has a positive score "
            "from a resolved forecast"
        )
        return weights
    uids, chain_weights = _apply_burn_allocation(positive_weights)
    _submit_weights(
        settings,
        uids,
        chain_weights,
    )
    return weights


def _apply_burn_allocation(
    positive_weights: Sequence[tuple[int, float]],
) -> tuple[list[int], list[float]]:
    if not 0.0 <= BURN_PERCENTAGE <= 1.0:
        raise ValueError(
            f"BURN_PERCENTAGE must be between 0.0 and 1.0, got {BURN_PERCENTAGE}"
        )

    miner_weights = [
        (int(uid), max(0.0, float(weight)))
        for uid, weight in positive_weights
        if int(uid) != BURN_UID and float(weight) > 0.0
    ]
    total = sum(weight for _uid, weight in miner_weights)
    if total <= 0.0:
        return [BURN_UID], [1.0]

    miner_percentage = 1.0 - BURN_PERCENTAGE
    uids = [uid for uid, _weight in miner_weights]
    weights = [(weight / total) * miner_percentage for _uid, weight in miner_weights]
    uids.append(BURN_UID)
    weights.append(BURN_PERCENTAGE)
    total_weight = sum(weights)
    return uids, [weight / total_weight for weight in weights]


def _submit_weights(settings: Settings, uids: Sequence[int], weights: Sequence[float]) -> None:
    try:
        import bittensor as bt
    except Exception as exc:
        raise RuntimeError("bittensor is required when DRY_RUN_WEIGHTS=false") from exc
    wallet = bt.wallet(name=settings.wallet_name, hotkey=settings.wallet_hotkey)
    subtensor = bt.subtensor(network=settings.subtensor_network)
    subtensor.set_weights(wallet, settings.netuid, list(uids), list(weights))
