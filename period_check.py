from __future__ import annotations

"""Forecast-period closeout checks."""

from sqlalchemy.exc import IntegrityError

from models import MinerRegistration, Submission, Task, as_utc, utcnow


def close_expired_tasks(session_factory) -> int:
    now = utcnow()
    closed = 0
    with session_factory() as session:
        tasks = session.query(Task).filter(Task.status == "open").all()
        active_miners = (
            session.query(MinerRegistration)
            .filter(MinerRegistration.is_active.is_(True))
            .all()
        )
        for task in tasks:
            deadline = as_utc(task.deadline)
            if deadline is None or deadline > now:
                continue
            task.status = "closed"
            task.closed_at = now
            closed += 1
            for miner in active_miners:
                existing = (
                    session.query(Submission)
                    .filter(
                        Submission.task_id == task.task_id,
                        Submission.miner_uid == miner.uid,
                    )
                    .first()
                )
                if existing is not None:
                    continue
                session.add(
                    Submission(
                        task_id=task.task_id,
                        miner_uid=miner.uid,
                        probability=None,
                        reasoning="",
                        submitted_at=now,
                        status="rejected",
                        rejection_kind="missing",
                        rejection_reason="miner did not submit before deadline",
                    )
                )
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise
    return closed
