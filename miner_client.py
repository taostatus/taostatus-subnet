from __future__ import annotations

"""Miner query transports, validation, and submission storage."""

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError

from config import Settings
from models import MinerRegistration, Submission, Task, as_utc, utcnow


@dataclass(frozen=True)
class MinerResponse:
    probability: Any
    reasoning: str
    submitted_at: Any = None
    raw_response: Optional[dict[str, Any]] = None


class MinerTransport:
    async def query(
        self, task: Task, miner: MinerRegistration, timeout_seconds: float
    ) -> Optional[MinerResponse]:
        raise NotImplementedError


class SimulatedMinerTransport(MinerTransport):
    async def query(
        self, task: Task, miner: MinerRegistration, timeout_seconds: float
    ) -> Optional[MinerResponse]:
        metadata = miner.metadata_json or {}
        if metadata.get("no_response"):
            await asyncio.sleep(min(0.01, timeout_seconds))
            return None
        if metadata.get("bad_probability"):
            return MinerResponse(
                probability=1.5,
                reasoning="Simulated invalid probability.",
                submitted_at=utcnow(),
                raw_response={"simulated": True},
            )
        skill = float(metadata.get("simulation_skill", _default_skill(miner.uid)))
        noise = _deterministic_noise(f"{miner.uid}:{task.task_id}", spread=0.05)
        probability = max(0.01, min(0.99, skill + noise))
        return MinerResponse(
            probability=probability,
            reasoning=f"Simulated deterministic forecast with skill={skill:.2f}.",
            submitted_at=utcnow(),
            raw_response={"simulated": True, "skill": skill, "noise": noise},
        )


class DendriteMinerTransport(MinerTransport):
    def __init__(self, wallet: Any = None, metagraph: Any = None, dendrite: Any = None):
        self.metagraph = metagraph
        if dendrite is not None:
            self.dendrite = dendrite
        else:
            try:
                import bittensor as bt
            except Exception as exc:
                raise RuntimeError("bittensor is required for real miner transport") from exc
            self.dendrite = bt.Dendrite(wallet=wallet)

    async def query(
        self, task: Task, miner: MinerRegistration, timeout_seconds: float
    ) -> Optional[MinerResponse]:
        from masxai.protocol import ForecastSynapse

        if self.metagraph is None:
            raise ValueError("metagraph is required for DendriteMinerTransport")
        axon = self.metagraph.axons[miner.uid]
        synapse = ForecastSynapse(
            forecast_id=task.task_id,
            question=task.question,
            event_type=task.category,
            issued_at=utcnow().timestamp(),
            resolve_at=as_utc(task.deadline).timestamp(),
            context=task.resolution_hint,
        )
        responses = await self.dendrite(
            axons=[axon],
            synapse=synapse,
            deserialize=False,
            timeout=timeout_seconds,
        )
        if not responses:
            return None
        response = responses[0]
        probability = getattr(response, "probability", None)
        if probability is None and getattr(response, "prediction", None) is not None:
            confidence = getattr(response, "confidence", None)
            if confidence is not None:
                probability = float(confidence) if response.prediction else 1.0 - float(confidence)
        return MinerResponse(
            probability=probability,
            reasoning=getattr(response, "reasoning", "") or "",
            submitted_at=getattr(response, "timestamp", None) or utcnow(),
            raw_response=getattr(response, "deserialize", lambda: {})(),
        )


def build_miner_transport(
    settings: Settings, wallet: Any = None, metagraph: Any = None, dendrite: Any = None
) -> MinerTransport:
    if settings.simulate_miners:
        return SimulatedMinerTransport()
    return DendriteMinerTransport(wallet=wallet, metagraph=metagraph, dendrite=dendrite)


async def query_miners(
    settings: Settings,
    session_factory,
    transport: Optional[MinerTransport] = None,
) -> int:
    transport = transport or build_miner_transport(settings)
    now = utcnow()
    with session_factory() as session:
        tasks = (
            session.query(Task)
            .filter(Task.status == "open")
            .all()
        )
        tasks = [task for task in tasks if as_utc(task.deadline) and as_utc(task.deadline) > now]
        miners = (
            session.query(MinerRegistration)
            .filter(MinerRegistration.is_active.is_(True))
            .all()
        )
        pairs: list[tuple[Task, MinerRegistration]] = []
        for task in tasks:
            for miner in miners:
                existing = (
                    session.query(Submission)
                    .filter(
                        Submission.task_id == task.task_id,
                        Submission.miner_uid == miner.uid,
                    )
                    .first()
                )
                if existing is None:
                    pairs.append((task, miner))

    semaphore = asyncio.Semaphore(settings.miner_max_concurrent_queries)
    async def _query_one(task: Task, miner: MinerRegistration) -> bool:
        async with semaphore:
            try:
                response = await asyncio.wait_for(
                    transport.query(task, miner, settings.miner_query_timeout_seconds),
                    timeout=settings.miner_query_timeout_seconds,
                )
            except asyncio.TimeoutError:
                return False
            except Exception as exc:
                store_submission(
                    session_factory,
                    task.task_id,
                    miner.uid,
                    MinerResponse(
                        probability=None,
                        reasoning="",
                        submitted_at=utcnow(),
                        raw_response={"error": str(exc)},
                    ),
                )
                return True
            if response is None:
                return False
            store_submission(session_factory, task.task_id, miner.uid, response)
            return True

    results = await asyncio.gather(*[_query_one(task, miner) for task, miner in pairs])
    return sum(1 for result in results if result)


def store_submission(
    session_factory,
    task_id: str,
    miner_uid: int,
    response: MinerResponse,
) -> Submission:
    with session_factory() as session:
        task = session.get(Task, task_id)
        miner = session.get(MinerRegistration, miner_uid)
        status, kind, reason = validate_submission(session, task, miner, response)
        submitted_at = as_utc(response.submitted_at) or utcnow()
        submission = Submission(
            task_id=task_id,
            miner_uid=miner_uid,
            probability=_coerce_probability(response.probability),
            reasoning=response.reasoning or "",
            submitted_at=submitted_at,
            status=status,
            rejection_kind=kind,
            rejection_reason=reason,
            raw_response=response.raw_response,
        )
        session.add(submission)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            duplicate = (
                session.query(Submission)
                .filter(Submission.task_id == task_id, Submission.miner_uid == miner_uid)
                .first()
            )
            if duplicate is not None:
                return duplicate
            raise
        return submission


def validate_submission(
    session,
    task: Optional[Task],
    miner: Optional[MinerRegistration],
    response: MinerResponse,
) -> tuple[str, Optional[str], Optional[str]]:
    if miner is None or not miner.is_active:
        return "rejected", "registration", "miner is not an active registered miner"
    if task is None or task.status != "open":
        return "rejected", "task", "task_id does not match an active task"
    if (
        session.query(Submission)
        .filter(Submission.task_id == task.task_id, Submission.miner_uid == miner.uid)
        .first()
        is not None
    ):
        return "rejected", "duplicate", "miner already has a submission for this task"
    if not response.reasoning or not response.reasoning.strip():
        return "rejected", "validation", "reasoning is required"
    submitted_at = as_utc(response.submitted_at) or utcnow()
    deadline = as_utc(task.deadline)
    if deadline is None or submitted_at >= deadline:
        return "rejected", "late", "submitted at or after the task deadline"
    try:
        probability = float(response.probability)
    except (TypeError, ValueError):
        return "rejected", "validation", "probability must be a float"
    if probability < 0.0 or probability > 1.0:
        return "rejected", "validation", "probability must be in [0, 1]"
    fresh_miner = session.get(MinerRegistration, miner.uid)
    if fresh_miner is None or not fresh_miner.is_active:
        return "rejected", "registration", "miner registration re-check failed"
    return "valid", None, None


def _coerce_probability(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _default_skill(uid: int) -> float:
    return max(0.2, min(0.9, 0.9 - (int(uid) % 5) * 0.15))


def _deterministic_noise(seed: str, spread: float) -> float:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    unit = int(digest[:8], 16) / 0xFFFFFFFF
    return (unit - 0.5) * 2.0 * spread
