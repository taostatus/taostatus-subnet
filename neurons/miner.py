"""
neurons/miner.py - MASXAI miner: LLM-key contribution pipeline.

A miner opts in to contribute an LLM API key as a resource for the protocol
backend. The miner never talks to the protocol directly and never sees its
own contributed key leave in plaintext -- it encrypts the key client-side for
the protocol's published public key, and the validator relays only that
opaque ciphertext onward.
"""

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


def _llm_key_contrib_config() -> typing.Optional[typing.Tuple[str, str, str]]:
    """Return (provider, model, api_key) if the operator has opted into the
    LLM-key contribution pipeline and configured it completely, else None.
    """
    if not _env_flag(C.LLM_KEY_CONTRIB_ENABLED_ENV, False):
        return None
    provider = os.getenv(C.LLM_KEY_CONTRIB_PROVIDER_ENV, "").strip()
    model = os.getenv(C.LLM_KEY_CONTRIB_MODEL_ENV, "").strip()
    api_key = os.getenv(C.LLM_KEY_CONTRIB_API_KEY_ENV, "").strip()
    if not provider or not model or not api_key:
        return None
    return provider, model, api_key


class Miner(BaseMinerNeuron):
    def __init__(self, config=None):
        load_env()
        super().__init__(config=config)
        llm_key_config = _llm_key_contrib_config()
        bt.logging.info(
            "LLM-key contribution | "
            f"enabled={llm_key_config is not None} "
            + (
                f"provider={llm_key_config[0]} model={llm_key_config[1]}"
                if llm_key_config is not None
                else ""
            )
        )
        bt.logging.info("MASXAI miner initialized.")

    async def forward(self, synapse: LLMKeySynapse) -> LLMKeySynapse:
        """Answer a request to contribute an LLM key, or decline cleanly.

        Never raises -- any failure (not opted in, bad protocol pubkey,
        disallowed provider/model, encryption error) falls back to
        has_key=False rather than crashing the axon route.
        """
        try:
            config = _llm_key_contrib_config()
            if config is None or not synapse.protocol_pubkey_b64:
                synapse.has_key = False
                return synapse

            provider, model, api_key = config
            if synapse.allowed_models and f"{provider}/{model}" not in synapse.allowed_models:
                bt.logging.debug(
                    f"llm-key: {provider}/{model} not in this round's allowed_models; declining"
                )
                synapse.has_key = False
                return synapse

            synapse.encrypted_key_blob = encrypt_for_protocol(
                api_key, synapse.protocol_pubkey_b64
            )
            synapse.has_key = True
            synapse.provider = provider
            synapse.model = model
            synapse.blob_encoding = "nacl-sealedbox-v1"
            synapse.pubkey_id_used = synapse.protocol_pubkey_id
            synapse.timestamp = _utc_now_iso()
        except Exception as e:  # noqa: BLE001 — never let forward crash
            bt.logging.warning(f"llm-key contribution failed, declining this round: {e}")
            synapse.has_key = False
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
