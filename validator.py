from __future__ import annotations

"""Single-loop orchestrator for the forecasting subnet validator."""

import asyncio
import logging
from dataclasses import dataclass

from config import Settings, load_settings
from db import init_db
from miner_client import build_miner_transport, query_miners
from miner_registry import refresh_miner_registry
from period_check import close_expired_tasks
from resolver import resolve_tasks
from scoring import score_resolved_tasks
from task_service import source_tasks
from weight_setter import set_weights


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Stage:
    name: str
    interval_seconds: int
    last_run: float = 0.0

    def due(self, now: float) -> bool:
        return self.last_run == 0.0 or now - self.last_run >= self.interval_seconds


async def run_validator(settings: Settings | None = None) -> None:
    settings = settings or load_settings()
    session_factory = init_db(settings)
    refresh_miner_registry(settings, session_factory)
    transport = build_miner_transport(settings)
    stages = {
        "tasks": Stage("tasks", 60),
        "miners": Stage("miners", settings.miner_query_interval_seconds),
        "period": Stage("period", settings.period_check_interval_seconds),
        "resolution": Stage("resolution", settings.resolution_interval_seconds),
        "weights": Stage("weights", settings.weight_set_interval_seconds),
    }
    logger.info("forecasting validator started with TASK_SOURCE=%s", settings.task_source)
    while True:
        now = asyncio.get_running_loop().time()
        if stages["tasks"].due(now):
            count = await source_tasks(settings, session_factory)
            logger.info("task sourcing upserted %s task(s)", count)
            stages["tasks"].last_run = now
        if stages["miners"].due(now):
            refresh_miner_registry(settings, session_factory)
            count = await query_miners(settings, session_factory, transport)
            logger.info("miner query stored %s submission(s)", count)
            stages["miners"].last_run = now
        if stages["period"].due(now):
            count = close_expired_tasks(session_factory)
            logger.info("period check closed %s task(s)", count)
            stages["period"].last_run = now
        if stages["resolution"].due(now):
            count = await resolve_tasks(settings, session_factory)
            scored = score_resolved_tasks(settings, session_factory)
            logger.info("resolved %s task(s), scored %s submission(s)", count, scored)
            stages["resolution"].last_run = now
        if stages["weights"].due(now):
            weights = set_weights(settings, session_factory)
            logger.info("weight stage updated %s miner weight(s)", len(weights))
            stages["weights"].last_run = now
        await asyncio.sleep(1.0)


if __name__ == "__main__":
    asyncio.run(run_validator())
