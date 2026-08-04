from __future__ import annotations

"""Brier, calibration, reliability profiles, and base score calculation."""

from collections import defaultdict

from config import Settings
from models import (
    MinerRegistration,
    ReliabilityProfile,
    Resolution,
    Submission,
    Task,
    utcnow,
)


def brier_score(probability: float, outcome: float) -> float:
    return (float(probability) - float(outcome)) ** 2


def score_resolved_tasks(settings: Settings, session_factory) -> int:
    scored = 0
    with session_factory() as session:
        resolved_tasks = (
            session.query(Task)
            .join(Resolution, Resolution.task_id == Task.task_id)
            .filter(Task.status == "resolved")
            .all()
        )
        for task in resolved_tasks:
            resolution = task.resolution
            for submission in task.submissions:
                if submission.status != "valid" or submission.scored_at is not None:
                    continue
                submission.brier_score = brier_score(submission.probability, resolution.outcome)
                submission.reward = 1.0 - submission.brier_score
                submission.scored_at = utcnow()
                scored += 1
        session.commit()
    rebuild_reliability_profiles(settings, session_factory)
    return scored


def rebuild_reliability_profiles(settings: Settings, session_factory) -> None:
    with session_factory() as session:
        miners = session.query(MinerRegistration).all()
        for miner in miners:
            submissions = (
                session.query(Submission)
                .filter(Submission.miner_uid == miner.uid)
                .order_by(Submission.submitted_at.asc(), Submission.id.asc())
                .all()
            )
            valid_scored = [
                submission
                for submission in submissions
                if submission.status == "valid" and submission.brier_score is not None
            ]
            invalid_count = sum(
                1
                for submission in submissions
                if submission.status == "rejected"
                and submission.rejection_kind not in {"late", "missing"}
            )
            late_missing_count = sum(
                1
                for submission in submissions
                if submission.status == "rejected"
                and submission.rejection_kind in {"late", "missing"}
            )
            profile = session.get(ReliabilityProfile, miner.uid)
            if profile is None:
                profile = ReliabilityProfile(miner_uid=miner.uid)
                session.add(profile)
            profile.valid_count = len(valid_scored)
            profile.invalid_count = invalid_count
            profile.late_missing_count = late_missing_count
            if valid_scored:
                briers = [float(submission.brier_score) for submission in valid_scored]
                profile.mean_brier = sum(briers) / len(briers)
                recent = briers[0]
                for brier in briers[1:]:
                    recent = settings.ema_alpha * brier + (1.0 - settings.ema_alpha) * recent
                profile.recent_brier = recent
            else:
                profile.mean_brier = 1.0
                profile.recent_brier = 1.0
            buckets = _build_calibration_buckets(valid_scored)
            profile.calibration_buckets = buckets
            profile.calibration_error = _calibration_error(buckets)
            profile.base_score = _base_score(settings, profile)
            profile.raw_weight = profile.base_score
            profile.updated_at = utcnow()
        session.commit()


def _build_calibration_buckets(valid_scored: list[Submission]) -> list[dict[str, float]]:
    bucket_map: dict[int, dict[str, float]] = defaultdict(
        lambda: {"count": 0, "predicted_sum": 0.0, "observed_sum": 0.0}
    )
    for submission in valid_scored:
        if submission.probability is None or submission.task is None or submission.task.resolution is None:
            continue
        bucket_index = min(9, max(0, int(float(submission.probability) * 10)))
        bucket = bucket_map[bucket_index]
        bucket["count"] += 1
        bucket["predicted_sum"] += float(submission.probability)
        bucket["observed_sum"] += float(submission.task.resolution.outcome)
    buckets = []
    for index in range(10):
        data = bucket_map[index]
        count = data["count"]
        buckets.append(
            {
                "lower": index / 10,
                "upper": (index + 1) / 10,
                "count": count,
                "predicted_sum": data["predicted_sum"],
                "observed_sum": data["observed_sum"],
                "avg_predicted": data["predicted_sum"] / count if count else 0.0,
                "avg_observed": data["observed_sum"] / count if count else 0.0,
            }
        )
    return buckets


def _calibration_error(buckets: list[dict[str, float]]) -> float:
    total_count = sum(bucket["count"] for bucket in buckets)
    if total_count == 0:
        return 0.0
    weighted_gap = 0.0
    for bucket in buckets:
        if bucket["count"]:
            weighted_gap += bucket["count"] * abs(bucket["avg_predicted"] - bucket["avg_observed"])
    return weighted_gap / total_count


def _base_score(settings: Settings, profile: ReliabilityProfile) -> float:
    valid = float(profile.valid_count)
    invalid = float(profile.invalid_count)
    late_missing = float(profile.late_missing_count)
    skill = max(0.0, 1.0 - float(profile.mean_brier))
    recent_skill = max(0.0, 1.0 - float(profile.recent_brier))
    valid_rate = valid / (valid + invalid) if valid + invalid > 0 else 0.0
    participation = (
        valid / (valid + invalid + late_missing)
        if valid + invalid + late_missing > 0
        else 0.0
    )
    base = (
        settings.weight_skill * skill
        + settings.weight_recent_skill * recent_skill
        + settings.weight_valid_rate * valid_rate
        + settings.weight_participation * participation
    )
    if profile.calibration_error > settings.calibration_error_threshold:
        excess = profile.calibration_error - settings.calibration_error_threshold
        penalty = min(1.0, excess * settings.calibration_penalty_factor)
        base *= 1.0 - penalty
    return max(0.0, base)
