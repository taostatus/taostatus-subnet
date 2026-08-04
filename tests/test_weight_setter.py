from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, MinerRegistration, ReliabilityProfile
from weight_setter import BURN_PERCENTAGE, BURN_UID, set_weights


def _session_factory():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _settings():
    return SimpleNamespace(
        dry_run_weights=False,
        wallet_name="validator",
        wallet_hotkey="default",
        subtensor_network="test",
        netuid=501,
    )


def test_set_weights_skips_chain_submit_without_positive_scores(monkeypatch):
    session_factory = _session_factory()
    with session_factory() as session:
        session.add(MinerRegistration(uid=1, hotkey="miner-1", is_active=True))
        session.add(ReliabilityProfile(miner_uid=1, base_score=0.0))
        session.commit()

    calls = []
    monkeypatch.setattr(
        "weight_setter._submit_weights",
        lambda settings, uids, weights: calls.append((uids, weights)),
    )

    weights = set_weights(_settings(), session_factory)

    assert weights == [(1, 0.0, 0.0)]
    assert calls == []


def test_set_weights_submits_only_positive_scored_miners(monkeypatch):
    session_factory = _session_factory()
    with session_factory() as session:
        session.add(MinerRegistration(uid=1, hotkey="miner-1", is_active=True))
        session.add(MinerRegistration(uid=2, hotkey="miner-2", is_active=True))
        session.add(ReliabilityProfile(miner_uid=1, base_score=0.75, valid_count=1))
        session.add(ReliabilityProfile(miner_uid=2, base_score=0.0, valid_count=0))
        session.commit()

    calls = []
    monkeypatch.setattr(
        "weight_setter._submit_weights",
        lambda settings, uids, weights: calls.append((uids, weights)),
    )

    weights = set_weights(_settings(), session_factory)

    assert weights == [(1, 0.75, 1.0), (2, 0.0, 0.0)]
    assert calls == [([1, BURN_UID], [1.0 - BURN_PERCENTAGE, BURN_PERCENTAGE])]


def test_set_weights_ignores_unresolved_positive_scores(monkeypatch):
    session_factory = _session_factory()
    with session_factory() as session:
        session.add(MinerRegistration(uid=1, hotkey="miner-1", is_active=True))
        session.add(ReliabilityProfile(miner_uid=1, base_score=0.75, valid_count=0))
        session.commit()

    calls = []
    monkeypatch.setattr(
        "weight_setter._submit_weights",
        lambda settings, uids, weights: calls.append((uids, weights)),
    )

    weights = set_weights(_settings(), session_factory)

    assert weights == [(1, 0.0, 0.0)]
    assert calls == []
