from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace

from nacl.public import PrivateKey

from masxai import constants as C
from masxai.protocol import LLMKeySynapse
from neurons.miner import Miner


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


def _clear_llm_key_env(monkeypatch):
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_ENABLED_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_MODEL_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, raising=False)


def _set_llm_key_env(monkeypatch, *, provider="openai", model="gpt-4o-mini", api_key="sk-test-123"):
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_ENABLED_ENV, "true")
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, provider)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_MODEL_ENV, model)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, api_key)


def _key_request_synapse(*, allowed_models=None) -> LLMKeySynapse:
    privkey = PrivateKey.generate()
    pubkey_b64 = base64.b64encode(bytes(privkey.public_key)).decode()
    return LLMKeySynapse(
        request_id="req-1",
        protocol_pubkey_id="v1",
        protocol_pubkey_b64=pubkey_b64,
        allowed_models=allowed_models or [],
    )


def test_forward_declines_when_not_opted_in(monkeypatch):
    _clear_llm_key_env(monkeypatch)
    miner = _miner(_FakeMetagraph())

    result = asyncio.run(miner.forward(_key_request_synapse()))

    assert result.has_key is False
    assert result.encrypted_key_blob == ""


def test_forward_declines_when_pubkey_missing(monkeypatch):
    _set_llm_key_env(monkeypatch)
    miner = _miner(_FakeMetagraph())
    synapse = LLMKeySynapse(request_id="req-1", protocol_pubkey_id="v1", protocol_pubkey_b64="")

    result = asyncio.run(miner.forward(synapse))

    assert result.has_key is False


def test_forward_declines_when_model_not_allowed(monkeypatch):
    _set_llm_key_env(monkeypatch)
    miner = _miner(_FakeMetagraph())
    synapse = _key_request_synapse(allowed_models=["anthropic/claude-3-5-sonnet-20241022"])

    result = asyncio.run(miner.forward(synapse))

    assert result.has_key is False
    assert result.encrypted_key_blob == ""


def test_forward_encrypts_when_opted_in_and_allowed(monkeypatch):
    _set_llm_key_env(monkeypatch)
    miner = _miner(_FakeMetagraph())
    synapse = _key_request_synapse(allowed_models=["openai/gpt-4o-mini"])

    result = asyncio.run(miner.forward(synapse))

    assert result.has_key is True
    assert result.provider == "openai"
    assert result.model == "gpt-4o-mini"
    assert result.encrypted_key_blob != ""
    assert result.pubkey_id_used == "v1"
    assert result.blob_encoding == "nacl-sealedbox-v1"


def test_blacklist_requires_permit_unconditionally(monkeypatch):
    # This synapse triggers a state-changing action (a key submission relayed
    # onward to the protocol backend), so a validator permit is always
    # required -- no env var or CLI flag disables this.
    miner = _miner(_FakeMetagraph(validator_permit=[True, False]))

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("miner-hotkey-1")))
    assert blacklisted is True
    assert "permit" in reason

    blacklisted, _ = asyncio.run(miner.blacklist(_synapse("validator-hotkey")))
    assert blacklisted is False


def test_blacklist_rejects_unregistered_hotkey():
    miner = _miner(_FakeMetagraph())

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("unknown-hotkey")))

    assert blacklisted is True
    assert "unregistered" in reason


def test_blacklist_rejects_when_permit_unavailable():
    miner = _miner(_FakeMetagraph(validator_permit=None))

    blacklisted, reason = asyncio.run(miner.blacklist(_synapse("miner-hotkey-1")))

    assert blacklisted is True
    assert "permit" in reason


def test_priority_returns_stake_for_known_hotkey():
    metagraph = _FakeMetagraph()
    metagraph.S = [100.0, 5.0]
    miner = _miner(metagraph)

    priority = asyncio.run(miner.priority(_synapse("miner-hotkey-1")))

    assert priority == 5.0


def test_priority_returns_zero_for_unknown_hotkey():
    miner = _miner(_FakeMetagraph())

    priority = asyncio.run(miner.priority(_synapse("unknown-hotkey")))

    assert priority == 0.0
