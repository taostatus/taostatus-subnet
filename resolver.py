from __future__ import annotations

"""Pluggable resolution source chain."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from config import Settings
from models import Resolution, Task, utcnow


@dataclass(frozen=True)
class ResolutionResult:
    outcome: float
    source: str
    metadata: dict[str, Any]


class ResolutionSource(Protocol):
    async def resolve(self, task: Task) -> Optional[ResolutionResult]:
        """Return 0.0/1.0 or decline with None."""


class PriceAPIResolutionSource:
    async def resolve(self, task: Task) -> Optional[ResolutionResult]:
        return None


class WebScrapeResolutionSource:
    async def resolve(self, task: Task) -> Optional[ResolutionResult]:
        return None


class ManualResolutionSource:
    def __init__(self, path: str):
        self.path = Path(path)

    async def resolve(self, task: Task) -> Optional[ResolutionResult]:
        if not self.path.exists():
            return None
        payload = json.loads(self.path.read_text())
        if task.task_id not in payload:
            return None
        entry = payload[task.task_id]
        if isinstance(entry, dict):
            outcome = entry.get("outcome")
            metadata = {key: value for key, value in entry.items() if key != "outcome"}
        else:
            outcome = entry
            metadata = {}
        if outcome not in (0, 0.0, 1, 1.0, False, True):
            raise ValueError(f"Manual resolution for {task.task_id} must be 0.0 or 1.0")
        return ResolutionResult(
            outcome=float(outcome),
            source="manual",
            metadata=metadata,
        )


def build_resolution_sources(settings: Settings) -> list[ResolutionSource]:
    return [
        PriceAPIResolutionSource(),
        WebScrapeResolutionSource(),
        ManualResolutionSource(settings.manual_resolution_path),
    ]


async def resolve_tasks(
    settings: Settings,
    session_factory,
    sources: Optional[list[ResolutionSource]] = None,
) -> int:
    sources = sources or build_resolution_sources(settings)
    resolved = 0
    with session_factory() as session:
        tasks = (
            session.query(Task)
            .filter(Task.status == "closed")
            .all()
        )
        task_ids = [task.task_id for task in tasks]

    for task_id in task_ids:
        with session_factory() as session:
            task = session.get(Task, task_id)
            if task is None or task.status != "closed":
                continue
            if session.query(Resolution).filter(Resolution.task_id == task_id).first():
                continue
        result: Optional[ResolutionResult] = None
        for source in sources:
            with session_factory() as session:
                task_for_source = session.get(Task, task_id)
            if task_for_source is None:
                break
            result = await source.resolve(task_for_source)
            if result is not None:
                break
        if result is None:
            continue
        with session_factory() as session:
            task = session.get(Task, task_id)
            if task is None:
                continue
            session.add(
                Resolution(
                    task_id=task_id,
                    outcome=result.outcome,
                    source=result.source,
                    metadata_json=result.metadata,
                    resolved_at=utcnow(),
                )
            )
            task.status = "resolved"
            task.updated_at = utcnow()
            session.commit()
            resolved += 1
    return resolved
