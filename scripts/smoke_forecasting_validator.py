from __future__ import annotations

"""End-to-end smoke test for the modular forecasting validator."""

import asyncio
import json
import os
from pathlib import Path
import sys
from datetime import timedelta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import load_settings
from db import init_db
from miner_client import query_miners
from miner_registry import refresh_miner_registry
from models import ReliabilityProfile, Resolution, Submission, utcnow
from period_check import close_expired_tasks
from providers.base import ProviderTask
from resolver import resolve_tasks
from scoring import score_resolved_tasks
from task_service import upsert_tasks
from weight_setter import set_weights


async def main() -> None:
    db_path = Path("/private/tmp/masxai_forecasting_smoke.db")
    manual_path = Path("/private/tmp/masxai_manual_resolutions.json")
    for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"), manual_path):
        if path.exists():
            path.unlink()

    os.environ.update(
        {
            "TASK_SOURCE": "bt_forecast",
            "BT_FORECAST_BASE_URL": "http://127.0.0.1:9",
            "BT_FORECAST_BEARER_TOKEN": "smoke-token",
            "DB_PATH": str(db_path),
            "SIMULATE_MINERS": "true",
            "MINER_REGISTRY_PATH": str(ROOT / "miners.json"),
            "DRY_RUN_WEIGHTS": "true",
            "MANUAL_RESOLUTION_PATH": str(manual_path),
            "MINER_QUERY_TIMEOUT_SECONDS": "2",
            "MINER_MAX_CONCURRENT_QUERIES": "8",
        }
    )
    settings = load_settings()
    session_factory = init_db(settings)
    refresh_miner_registry(settings, session_factory)

    deadline = (utcnow() + timedelta(seconds=2)).replace(microsecond=0)
    task = ProviderTask(
        task_id="smoke-task-yes",
        question="Will this deterministic smoke-test event resolve YES?",
        category="test",
        deadline=deadline,
        resolution_hint="Manual smoke-test resolution.",
        source="smoke",
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    upsert_tasks(session_factory, [task])

    submitted = await query_miners(settings, session_factory)
    await asyncio.sleep(2.2)
    closed = close_expired_tasks(session_factory)
    manual_path.write_text(
        json.dumps({"smoke-task-yes": {"outcome": 1.0, "note": "scripted smoke outcome"}})
    )
    resolved = await resolve_tasks(settings, session_factory)
    scored = score_resolved_tasks(settings, session_factory)
    weights = set_weights(settings, session_factory)

    with session_factory() as session:
        resolution = session.query(Resolution).filter(Resolution.task_id == "smoke-task-yes").one()
        rows = (
            session.query(Submission, ReliabilityProfile)
            .join(ReliabilityProfile, ReliabilityProfile.miner_uid == Submission.miner_uid)
            .filter(Submission.task_id == "smoke-task-yes")
            .order_by(Submission.miner_uid.asc())
            .all()
        )
        print("smoke task:", task.task_id)
        print("submitted:", submitted, "closed:", closed, "resolved:", resolved, "scored:", scored)
        print("outcome:", resolution.outcome)
        print("uid\tbrier\tbase_score\tnormalized_weight")
        best_uid = None
        best_brier = None
        best_weight_uid = None
        best_weight = None
        for submission, profile in rows:
            brier = submission.brier_score
            print(
                f"{submission.miner_uid}\t{brier:.6f}\t"
                f"{profile.base_score:.6f}\t{profile.normalized_weight:.6f}"
            )
            if brier is not None and (best_brier is None or brier < best_brier):
                best_uid = submission.miner_uid
                best_brier = brier
            if best_weight is None or profile.normalized_weight > best_weight:
                best_weight_uid = submission.miner_uid
                best_weight = profile.normalized_weight
        weight_sum = sum(weight for _uid, _raw, weight in weights)
        print(f"weight_sum={weight_sum:.9f}")
        assert submitted == 4
        assert closed == 1
        assert resolved == 1
        assert scored == 4
        assert abs(weight_sum - 1.0) < 1e-9
        assert best_uid == best_weight_uid
        print(f"best_uid={best_uid} has lowest Brier and highest normalized weight")


if __name__ == "__main__":
    asyncio.run(main())
