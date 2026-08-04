from __future__ import annotations

"""Provider-neutral task schema."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from models import as_utc


@dataclass(frozen=True)
class ProviderTask:
    task_id: str
    question: str
    category: str
    deadline: datetime
    resolution_hint: str
    source: str
    schema_version: str = "1.0"
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def normalized_deadline(self) -> datetime:
        deadline = as_utc(self.deadline)
        if deadline is None:
            raise ValueError(f"Task {self.task_id} is missing a deadline")
        return deadline


class TaskProvider(Protocol):
    async def fetch_tasks(self) -> list[ProviderTask]:
        """Fetch and normalize tasks from an upstream source."""
