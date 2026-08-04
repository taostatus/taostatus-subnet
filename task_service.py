from __future__ import annotations

"""Task sourcing and storage."""

from config import Settings
from models import Task, as_utc, utcnow
from providers.base import ProviderTask, TaskProvider
from providers.llm_provider import LLMTaskProvider
from providers.bt_forecast_provider import BTForecastTaskProvider


def build_task_provider(settings: Settings, session_factory) -> TaskProvider:
    if settings.task_source == "bt_forecast":
        return BTForecastTaskProvider(settings=settings, session_factory=session_factory)
    if settings.task_source == "llm":
        return LLMTaskProvider(settings=settings)
    raise ValueError(f"Unsupported TASK_SOURCE={settings.task_source!r}")


async def source_tasks(settings: Settings, session_factory) -> int:
    provider = build_task_provider(settings, session_factory)
    tasks = await provider.fetch_tasks()
    return upsert_tasks(session_factory, tasks)


def upsert_tasks(session_factory, provider_tasks: list[ProviderTask]) -> int:
    count = 0
    with session_factory() as session:
        for item in provider_tasks:
            task = session.get(Task, item.task_id)
            now = utcnow()
            if task is None:
                task = Task(task_id=item.task_id, source=item.source)
                session.add(task)
            task.question = item.question
            task.category = item.category
            task.deadline = item.normalized_deadline()
            task.resolution_hint = item.resolution_hint
            task.schema_version = item.schema_version
            task.created_at = as_utc(item.created_at) or task.created_at or now
            task.updated_at = as_utc(item.updated_at) or now
            if task.status not in {"closed", "resolved"}:
                task.status = "open"
            count += 1
        session.commit()
    return count
