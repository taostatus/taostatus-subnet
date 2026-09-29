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

SECURITY_SYNAPSE_VERSION = 2


class SecurityAgentSynapse(bt.Synapse):
    """One ask-for-agent-image round trip (v2: encrypted-blob transport).

    A public Docker image lets any competing miner pull and read the agent's
    code. So v2 moves the primary path to an *encrypted* one, mirroring the
    LLM-key track: the validator publishes a NaCl SealedBox public key in the
    request; the miner encrypts a `docker save` tarball of its agent for that
    key and returns only a URL to the opaque ciphertext plus its sha256. The
    validator downloads the blob, decrypts it with its private key, and loads
    the image locally. A peer that fetches the same URL gets ciphertext it
    cannot decrypt.

    Because the validator must *run* the image, it (unlike the LLM-key backend
    relay) does decrypt -- so this protects a miner from other miners, not from
    the validator, which necessarily sees the plaintext image at run time.

    The plaintext `image_ref` path is kept as an optional fallback (a public
    registry ref), so a v1 miner or a deliberately-public agent still works and
    migration is smooth. When both are set the encrypted blob wins.

    Request (set by validator):
        request_id           uuid4 hex, unique per ask cycle
        validator_pubkey_b64 base64 NaCl SealedBox public key the miner encrypts
                             its agent tarball for -- the validator holds the
                             matching private key and is the only party that can
                             decrypt. Authenticated by the signed axon exchange,
                             so no separate key transfer is needed.
        pubkey_id            short id of the validator's current keypair, echoed
                             back so a rotated key is detectable
        issued_at            unix seconds
        version              security protocol version

    Response (set by miner):
        has_agent            False/None if the operator hasn't opted in this
                             round; True iff a blob (or image_ref) is provided
        blob_url             URL the validator downloads the encrypted tarball
                             from (the miner hosts it; the bytes are opaque)
        ciphertext_sha256    hex sha256 of the exact blob bytes, so the validator
                             can verify the download before decrypting
        blob_encoding        self-describing tag, e.g. "nacl-sealedbox-v1"
        pubkey_id_used       echoes the request's pubkey_id
        image_ref            OPTIONAL plaintext fallback: a public registry ref,
                             used only when blob_url is empty
        timestamp            ISO8601 generation timestamp
    """

    # ---- request ----
    request_id: str = ""
    validator_pubkey_b64: str = ""
    pubkey_id: str = ""
    issued_at: float = 0.0
    version: int = SECURITY_SYNAPSE_VERSION

    # ---- response ----
    has_agent: Optional[bool] = pydantic.Field(default=None)
    blob_url: str = ""
    ciphertext_sha256: str = ""
    blob_encoding: str = ""
    pubkey_id_used: str = ""
    image_ref: str = ""
    timestamp: str = ""

    def deserialize(self) -> dict[str, Any]:
        """Validators call this to read the miner's agent submission."""
        return {
            "has_agent": self.has_agent,
            "blob_url": self.blob_url,
            "ciphertext_sha256": self.ciphertext_sha256,
            "blob_encoding": self.blob_encoding,
            "pubkey_id_used": self.pubkey_id_used,
            "image_ref": self.image_ref,
            "timestamp": self.timestamp,
        }
