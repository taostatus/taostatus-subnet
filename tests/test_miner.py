from __future__ import annotations

import asyncio
import base64
import json
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
    monkeypatch.delenv(C.LLM_KEYS_JSON_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_MODEL_ENV, raising=False)
    monkeypatch.delenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, raising=False)


def _set_llm_key_env(monkeypatch, *, provider="openai", model="gpt-4o-mini", api_key="sk-test-123"):
    """Legacy single-key triple -- still honored as slot 0."""
    _clear_llm_key_env(monkeypatch)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_ENABLED_ENV, "true")
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, provider)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_MODEL_ENV, model)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, api_key)


def _set_llm_keys_json_env(monkeypatch, entries):
    _clear_llm_key_env(monkeypatch)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_ENABLED_ENV, "true")
    monkeypatch.setenv(C.LLM_KEYS_JSON_ENV, json.dumps(entries))


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
    assert result.keys == []


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
    assert result.keys == []


def test_forward_encrypts_when_opted_in_and_allowed(monkeypatch):
    # Legacy single-key env config still contributes, as slot 0.
    _set_llm_key_env(monkeypatch)
    miner = _miner(_FakeMetagraph())
    synapse = _key_request_synapse(allowed_models=["openai/gpt-4o-mini"])

    result = asyncio.run(miner.forward(synapse))

    assert result.has_key is True
    assert len(result.keys) == 1
    key = result.keys[0]
    assert key["slot"] == 0
    assert key["provider"] == "openai"
    assert key["model"] == "gpt-4o-mini"
    assert key["encrypted_key_blob"] != ""
    assert key["pubkey_id_used"] == "v1"
    assert key["blob_encoding"] == "nacl-sealedbox-v1"


def test_forward_sends_every_configured_key_with_stable_slots(monkeypatch):
    _set_llm_keys_json_env(monkeypatch, [
        {"provider": "openai", "model": "gpt-4o", "api_key": "sk-a"},
        {"provider": "openai", "model": "gpt-4o", "api_key": "sk-b"},  # same model twice: capacity stacking
        {"provider": "anthropic", "model": "claude-3-5-sonnet-20241022", "api_key": "sk-c"},
    ])
    miner = _miner(_FakeMetagraph())
    synapse = _key_request_synapse(
        allowed_models=["openai/gpt-4o", "anthropic/claude-3-5-sonnet-20241022"],
    )

    result = asyncio.run(miner.forward(synapse))

    assert result.has_key is True
    assert [k["slot"] for k in result.keys] == [0, 1, 2]
    assert [k["model"] for k in result.keys] == [
        "gpt-4o", "gpt-4o", "claude-3-5-sonnet-20241022",
    ]
    # each slot's blob is its own key, independently encrypted
    assert len({k["encrypted_key_blob"] for k in result.keys}) == 3


def test_forward_skips_disallowed_slot_but_keeps_the_rest(monkeypatch):
    # Slot numbers stay stable even when a middle slot is skipped -- the
    # backend replaces by slot, so renumbering would swap keys around.
    _set_llm_keys_json_env(monkeypatch, [
        {"provider": "openai", "model": "gpt-4o", "api_key": "sk-a"},
        {"provider": "deepseek", "model": "not-allowed-model", "api_key": "sk-b"},
        {"provider": "openai", "model": "gpt-4o", "api_key": "sk-c"},
    ])
    miner = _miner(_FakeMetagraph())
    synapse = _key_request_synapse(allowed_models=["openai/gpt-4o"])

    result = asyncio.run(miner.forward(synapse))

    assert [k["slot"] for k in result.keys] == [0, 2]


def test_configs_cap_at_max_and_skip_malformed(monkeypatch):
    from neurons.miner import _llm_key_contrib_configs

    entries = [{"provider": "openai", "model": "gpt-4o", "api_key": f"sk-{i}"} for i in range(7)]
    entries.insert(2, {"provider": "openai"})  # malformed: no model/api_key
    _set_llm_keys_json_env(monkeypatch, entries)

    configs = _llm_key_contrib_configs()

    assert len(configs) == C.LLM_KEY_MAX_KEYS_PER_HOTKEY
    assert all(len(c) == 3 for c in configs)


def test_configs_empty_on_malformed_json(monkeypatch):
    from neurons.miner import _llm_key_contrib_configs

    _clear_llm_key_env(monkeypatch)
    monkeypatch.setenv(C.LLM_KEY_CONTRIB_ENABLED_ENV, "true")
    monkeypatch.setenv(C.LLM_KEYS_JSON_ENV, "{not json")

    assert _llm_key_contrib_configs() == []


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
