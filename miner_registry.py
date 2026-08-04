from __future__ import annotations

"""Miner registry refresh from a live metagraph or a local JSON file."""

import json
from pathlib import Path
from typing import Any

from config import Settings
from models import MinerRegistration, utcnow


def refresh_miner_registry(settings: Settings, session_factory, metagraph: Any = None) -> int:
    if settings.simulate_miners:
        miners = _load_local_miners(settings.miner_registry_path)
    else:
        miners = _miners_from_metagraph(metagraph)
    return upsert_miners(session_factory, miners)


def upsert_miners(session_factory, miners: list[dict[str, Any]]) -> int:
    active_uids = {int(item["uid"]) for item in miners}
    with session_factory() as session:
        for existing in session.query(MinerRegistration).all():
            if existing.uid not in active_uids:
                existing.is_active = False
                existing.updated_at = utcnow()
        for item in miners:
            uid = int(item["uid"])
            miner = session.get(MinerRegistration, uid)
            if miner is None:
                miner = MinerRegistration(uid=uid, registered_at=utcnow())
                session.add(miner)
            miner.hotkey = str(item.get("hotkey") or f"sim-hotkey-{uid}")
            miner.axon = item.get("axon")
            miner.is_active = bool(item.get("is_active", True))
            miner.metadata_json = {
                key: value
                for key, value in item.items()
                if key not in {"uid", "hotkey", "axon", "is_active"}
            }
            miner.updated_at = utcnow()
        session.commit()
    return len(miners)


def _load_local_miners(path: str) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text())
    if isinstance(payload, dict):
        miners = payload.get("miners", [])
    else:
        miners = payload
    if not isinstance(miners, list):
        raise ValueError("MINER_REGISTRY_PATH must contain a JSON list or {\"miners\": [...]}")
    return miners


def _miners_from_metagraph(metagraph: Any) -> list[dict[str, Any]]:
    if metagraph is None:
        raise ValueError("A live metagraph is required when SIMULATE_MINERS=false")
    count = int(getattr(metagraph, "n"))
    miners: list[dict[str, Any]] = []
    for uid in range(count):
        axon = metagraph.axons[uid]
        miners.append(
            {
                "uid": uid,
                "hotkey": metagraph.hotkeys[uid],
                "axon": repr(axon),
                "is_active": bool(getattr(axon, "is_serving", False)),
            }
        )
    return miners
