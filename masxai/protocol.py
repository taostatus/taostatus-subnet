from __future__ import annotations

"""
masxai/protocol.py - wire protocol for the MASXAI subnet.

LLMKeySynapse is the subnet's sole synapse: miners who opt in contribute an
LLM API key to the protocol backend as a resource. The validator is a pure
relay -- it holds no cryptography and never sees the plaintext key, only an
opaque ciphertext blob encrypted by the miner for the protocol's public key.
"""

from enum import Enum
from typing import Any, Optional

import pydantic

from masxai.bt_compat import bt

SYNAPSE_VERSION = 5


class LLMKeySynapse(bt.Synapse):
    """
    A single ask-for-contributed-LLM-key round trip.

    The validator invents no cryptography and holds no keypair: it fetches
    protocol_pubkey_b64/allowed_models from the protocol backend and relays
    them verbatim in the request, then relays whatever ciphertext the miner
    returns straight to the protocol. This is what makes "the validator must
    never see the plaintext key" true by construction, not just by discipline.

    Request (set by validator):
        request_id          uuid4 hex, unique per ask cycle
        protocol_pubkey_id  id of the protocol's current transport keypair
        protocol_pubkey_b64 base64 NaCl SealedBox public key, fetched from the
                             protocol and relayed here -- the only way it
                             reaches the miner, since miners never call the
                             protocol directly
        allowed_models       list of "provider/model" strings, also relayed
                             from the protocol, so a miner can self-reject
                             before bothering to encrypt anything ineligible
        issued_at            unix seconds
        version               protocol version

    Response (set by miner):
        has_key              False/None if the operator hasn't opted in this
                             round -- a miner must never be forced to answer
        provider             plaintext, e.g. "openai" -- not sensitive
        model                plaintext, e.g. "gpt-4o-mini" -- not sensitive
        encrypted_key_blob   base64 SealedBox ciphertext of the raw key,
                             opaque to the validator
        blob_encoding        self-describing tag (e.g. "nacl-sealedbox-v1") so
                             a future scheme change doesn't force another
                             SYNAPSE_VERSION bump
        pubkey_id_used        echoes the request's protocol_pubkey_id, so the
                             protocol knows which private key to decrypt with
        timestamp             ISO8601 generation timestamp
    """

    # ---- request ----
    request_id: str = ""
    protocol_pubkey_id: str = ""
    protocol_pubkey_b64: str = ""
    allowed_models: list[str] = pydantic.Field(default_factory=list)
    issued_at: float = 0.0
    version: int = SYNAPSE_VERSION

    # ---- response ----
    has_key: Optional[bool] = pydantic.Field(default=None)
    provider: str = ""
    model: str = ""
    encrypted_key_blob: str = ""
    blob_encoding: str = "nacl-sealedbox-v1"
    pubkey_id_used: str = ""
    timestamp: str = ""

    def deserialize(self) -> dict[str, Any]:
        """Validators call this to read the miner's key submission."""
        return {
            "has_key": self.has_key,
            "provider": self.provider,
            "model": self.model,
            "encrypted_key_blob": self.encrypted_key_blob,
            "blob_encoding": self.blob_encoding,
            "pubkey_id_used": self.pubkey_id_used,
            "timestamp": self.timestamp,
        }
