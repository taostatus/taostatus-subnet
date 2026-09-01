"""
neurons/miner.py - MASXAI miner: LLM-key contribution pipeline.

A miner opts in to contribute up to LLM_KEY_MAX_KEYS_PER_HOTKEY (5) LLM API
keys as a resource for the protocol backend. The miner never talks to the
protocol directly and never sees a contributed key leave in plaintext -- it
encrypts each key client-side for the protocol's published public key, and
the validator relays only those opaque ciphertexts onward.
"""

import json
import os
import sys
import time
import typing
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masxai.protocol import LLMKeySynapse
from masxai import constants as C
from masxai.bt_compat import bt
from masxai.env import load_env
from masxai.llm_key_crypto import encrypt_for_protocol

# Provided by the bittensor-subnet-template fork:
try:
    from template.base.miner import BaseMinerNeuron
except Exception:
    class BaseMinerNeuron:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("BaseMinerNeuron requires a working bittensor install")


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _llm_key_contrib_configs() -> list[typing.Tuple[str, str, str]]:
    """Return the operator's configured keys as [(provider, model, api_key)],
    capped at LLM_KEY_MAX_KEYS_PER_HOTKEY. Empty when not opted in or nothing
    is configured completely.

    MASXAI_LLM_KEYS_JSON (a JSON array of {provider, model, api_key}) is the
    multi-key config; list order is the slot order. The legacy single-key
    MASXAI_LLM_KEY_CONTRIB_* triple is still honored as slot 0 when the JSON
    env is unset. A malformed JSON document or entry is skipped with a
    warning rather than crashing the miner.
    """
    if not _env_flag(C.LLM_KEY_CONTRIB_ENABLED_ENV, False):
        return []

    raw_json = os.getenv(C.LLM_KEYS_JSON_ENV, "").strip()
    if raw_json:
        try:
            entries = json.loads(raw_json)
        except json.JSONDecodeError as e:
            bt.logging.warning(f"llm-key: {C.LLM_KEYS_JSON_ENV} is not valid JSON ({e}); contributing nothing")
            return []
        if not isinstance(entries, list):
            bt.logging.warning(f"llm-key: {C.LLM_KEYS_JSON_ENV} must be a JSON array; contributing nothing")
            return []
        configs: list[typing.Tuple[str, str, str]] = []
        for i, entry in enumerate(entries):
            if len(configs) >= C.LLM_KEY_MAX_KEYS_PER_HOTKEY:
                bt.logging.warning(
                    f"llm-key: more than {C.LLM_KEY_MAX_KEYS_PER_HOTKEY} keys configured; "
                    "ignoring the extras"
                )
                break
            if not isinstance(entry, dict):
                bt.logging.warning(f"llm-key: entry #{i} is not an object; skipping it")
                continue
            provider = str(entry.get("provider", "")).strip()
            model = str(entry.get("model", "")).strip()
            api_key = str(entry.get("api_key", "")).strip()
            if not provider or not model or not api_key:
                bt.logging.warning(f"llm-key: entry #{i} is missing provider/model/api_key; skipping it")
                continue
            configs.append((provider, model, api_key))
        return configs

    provider = os.getenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, "").strip()
    model = os.getenv(C.LLM_KEY_CONTRIB_MODEL_ENV, "").strip()
    api_key = os.getenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, "").strip()
    if not provider or not model or not api_key:
        return []
    return [(provider, model, api_key)]


class Miner(BaseMinerNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        configs = _llm_key_contrib_configs()
        bt.logging.info(
            "LLM-key contribution | "
            f"enabled={bool(configs)} keys={len(configs)} "
            + " ".join(f"slot{i}={p}/{m}" for i, (p, m, _) in enumerate(configs))
        )
        bt.logging.info("MASXAI miner initialized.")

    async def forward(self, synapse: LLMKeySynapse) -> LLMKeySynapse:
        """Answer a request to contribute LLM keys, or decline cleanly.

        Each configured key is encrypted independently and sent with its
        slot (= its index in the configured list, stable across asks so a
        config edit replaces exactly that slot on the backend). A key whose
        provider/model isn't in this round's allowed list is skipped, not a
        reason to withhold the others. Never raises -- any failure (not
        opted in, bad protocol pubkey, encryption error) falls back to
        has_key=False rather than crashing the axon route.
        """
        try:
            configs = _llm_key_contrib_configs()
            if not configs or not synapse.protocol_pubkey_b64:
                synapse.has_key = False
                return synapse

            keys: list[dict] = []
            for slot, (provider, model, api_key) in enumerate(configs):
                if synapse.allowed_models and f"{provider}/{model}" not in synapse.allowed_models:
                    bt.logging.debug(
                        f"llm-key: slot {slot} ({provider}/{model}) not in this round's "
                        "allowed_models; skipping that slot"
                    )
                    continue
                keys.append({
                    "slot": slot,
                    "provider": provider,
                    "model": model,
                    "encrypted_key_blob": encrypt_for_protocol(
                        api_key, synapse.protocol_pubkey_b64
                    ),
                    "blob_encoding": "nacl-sealedbox-v1",
                    "pubkey_id_used": synapse.protocol_pubkey_id,
                })

            synapse.keys = keys
            synapse.has_key = bool(keys)
            synapse.timestamp = _utc_now_iso()
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"llm-key contribution failed, declining this round: {e}")
            synapse.has_key = False
            synapse.keys = []
        return synapse

    async def blacklist(self, synapse: LLMKeySynapse) -> typing.Tuple[bool, str]:
        """Reject non-registered or non-validator hotkeys.

        A validator permit is always required (not gated behind an opt-in
        flag) -- this synapse triggers a state-changing, security-sensitive
        action (a key submission relayed onward to the protocol backend) on
        every accepted response.
        """
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return True, "missing dendrite/hotkey"

        hotkey = synapse.dendrite.hotkey
        if hotkey not in self.metagraph.hotkeys:
            return True, f"unregistered hotkey {hotkey}"

        uid = self.metagraph.hotkeys.index(hotkey)
        permits = getattr(self.metagraph, "validator_permit", None)
        if permits is None:
            return True, "validator permit unavailable"
        if not bool(permits[uid]):
            return True, "no validator permit"
        return False, f"accepted from uid {uid}"

    async def priority(self, synapse: LLMKeySynapse) -> float:
        """Prioritize higher-stake callers. Standard template pattern."""
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            return 0.0
        try:
            uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        except ValueError:
            return 0.0
        return float(self.metagraph.S[uid])


if __name__ == "__main__":
    with Miner() as miner:
        while True:
            bt.logging.info(f"MASXAI miner alive | {time.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(30)
