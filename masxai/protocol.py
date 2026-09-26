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

SYNAPSE_VERSION = 6

# Mirrors the protocol backend's llm_key_max_keys_per_hotkey -- enforced on
# both ends of the wire (miner caps what it sends, validator caps what it
# relays), so a hostile peer can't inflate the batch.
MAX_KEYS_PER_MINER = 5


class LLMKeySynapse(bt.Synapse):
    """
    A single ask-for-contributed-LLM-keys round trip (v6: up to
    MAX_KEYS_PER_MINER keys per miner, replacing v5's single-key fields).

    The validator invents no cryptography and holds no keypair: it fetches
    protocol_pubkey_b64/allowed_models from the protocol backend and relays
    them verbatim in the request, then relays whatever ciphertexts the miner
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
                             round -- a miner must never be forced to answer;
                             True iff `keys` is non-empty
        keys                 list of key dicts, one per configured slot:
                               slot                index in the miner's key
                                                    list (0..MAX-1) -- a
                                                    resubmission for a slot
                                                    replaces that slot's key
                               provider            plaintext, e.g. "openai"
                               model               plaintext, e.g. "gpt-4o"
                               encrypted_key_blob  base64 SealedBox ciphertext
                                                    of the raw key, opaque to
                                                    the validator
                               blob_encoding       self-describing tag (e.g.
                                                    "nacl-sealedbox-v1")
                               pubkey_id_used      echoes protocol_pubkey_id
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
    keys: list[dict[str, Any]] = pydantic.Field(default_factory=list)
    timestamp: str = ""

    def deserialize(self) -> dict[str, Any]:
        """Validators call this to read the miner's key submissions."""
        return {
            "has_key": self.has_key,
            "keys": self.keys,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Security-audit track
# ---------------------------------------------------------------------------
# The second emission path (see SECURITY_VALIDATOR.md). Independent of
# LLMKeySynapse above: a miner contributes a security-testing agent packaged as
# a Docker image rather than an LLM key. The validator asks for the image
# reference, then pulls and evaluates it with the secqurityVali pipeline -- the
# validator never trusts anything the miner says about the image beyond the
# reference itself.

SECURITY_SYNAPSE_VERSION = 1


class SecurityAgentSynapse(bt.Synapse):
    """One ask-for-agent-image round trip.

    The miner returns only a reference to a Docker image (a registry ref such
    as ghcr.io/org/agent:0.1.0, or repo@sha256:...). Everything else about the
    image -- whether it is really an image, whether it is safe, whether it does
    the job -- is decided by the validator pulling and running it, never by the
    miner's word. So this wire contract is deliberately thin: the reference is
    the only miner-supplied field, and it is treated as untrusted input.

    Request (set by validator):
        request_id   uuid4 hex, unique per ask cycle
        issued_at    unix seconds
        version      security protocol version

    Response (set by miner):
        has_agent    False/None if the operator hasn't opted in this round --
                     a miner is never forced to answer; True iff image_ref set
        image_ref    the Docker image reference to evaluate
        timestamp    ISO8601 generation timestamp
    """

    # ---- request ----
    request_id: str = ""
    issued_at: float = 0.0
    version: int = SECURITY_SYNAPSE_VERSION

    # ---- response ----
    has_agent: Optional[bool] = pydantic.Field(default=None)
    image_ref: str = ""
    timestamp: str = ""

    def deserialize(self) -> dict[str, Any]:
        """Validators call this to read the miner's agent submission."""
        return {
            "has_agent": self.has_agent,
            "image_ref": self.image_ref,
            "timestamp": self.timestamp,
        }
