from __future__ import annotations

import asyncio
from types import SimpleNamespace

from masxai import constants as C
from neurons.miner import Miner, _timeout_margin_warning


class _FakeMetagraph:
    hotkeys = ["validator-hotkey", "miner-hotkey-1"]

    def __init__(self, validator_permit=None):
        self.validator_permit = validator_permit


def _miner(metagraph: _FakeMetagraph) -> Miner:
    miner = Miner.__new__(Miner)
    miner.metagraph = metagraph
    miner.config = SimpleNamespace(blacklist=SimpleNamespace(force_validator_permit=False))
    return miner


def _synapse(hotkey):
    return SimpleNamespace(dendrite=SimpleNamespace(hotkey=hotkey))


def test_timeout_margin_warning_silent_with_headroom():
    resolved = C.QUERY_TIMEOUT - C.GEMINI_TIMEOUT_MARGIN_SECONDS - 1.0

    assert _timeout_margin_warning(resolved) is None


def test_timeout_margin_warning_fires_when_too_close():
    warning = _timeout_margin_warning(C.QUERY_TIMEOUT - 1.0)

    assert warning is not None
    assert "GEMINI_TIMEOUT" in warning
    assert "QUERY_TIMEOUT" in warning


def test_blacklist_rejects_unregistered_hotkey():
    miner = _miner(_FakeMetagraph())

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("unknown-hotkey")))

    assert blacklisted is True
    assert "unregistered" in reason


def test_blacklist_allows_registered_hotkey_when_permit_not_required(monkeypatch):
    monkeypatch.delenv(C.MINER_REQUIRE_VALIDATOR_PERMIT_ENV, raising=False)
    miner = _miner(_FakeMetagraph())

    blacklisted, _ = asyncio.run(miner.blacklist(_synapse("miner-hotkey-1")))

    assert blacklisted is False


def test_blacklist_enforces_permit_via_env_var(monkeypatch):
    monkeypatch.setenv(C.MINER_REQUIRE_VALIDATOR_PERMIT_ENV, "true")
    miner = _miner(_FakeMetagraph(validator_permit=[True, False]))

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("miner-hotkey-1")))
    assert blacklisted is True
    assert "permit" in reason

    blacklisted, _ = asyncio.run(miner.blacklist(_synapse("validator-hotkey")))
    assert blacklisted is False


def test_blacklist_enforces_permit_via_cli_flag_even_without_env(monkeypatch):
    # Regression guard: --blacklist.force_validator_permit previously only
    # silenced the base class's warning without this miner's blacklist()
    # actually reading it.
    monkeypatch.delenv(C.MINER_REQUIRE_VALIDATOR_PERMIT_ENV, raising=False)
    miner = _miner(_FakeMetagraph(validator_permit=[True, False]))
    miner.config.blacklist.force_validator_permit = True

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("miner-hotkey-1")))

    assert blacklisted is True
    assert "permit" in reason
