from __future__ import annotations

"""Miner-side half of the LLM-key transport encryption.

Only an encrypt function exists here -- the miner has no keypair of its own
and never decrypts anything. NaCl SealedBox is purpose-built for "anonymous
sender encrypts to a recipient's public key, sender needs no durable
identity," which fits: the miner's only identity in this system is its
Bittensor hotkey, already authenticated by the signed dendrite/axon exchange.

The matching decrypt lives in the protocol backend
(BT-Arena_next_phase/backend/app/infra/llm_keys/crypto.py), never in this subnet repo.
"""

import base64

from nacl.public import PublicKey, SealedBox


class LLMKeyEncryptError(ValueError):
    """Raised when the supplied protocol public key is malformed."""


def encrypt_for_protocol(raw_key: str, protocol_pubkey_b64: str) -> str:
    """Encrypt `raw_key` for the protocol's published public key.

    Returns base64 ciphertext, safe to place directly in
    LLMKeySynapse.encrypted_key_blob. Non-deterministic across calls (SealedBox
    includes a fresh ephemeral key each time), so callers should not expect
    the same input to produce the same ciphertext twice.
    """
    try:
        pubkey_bytes = base64.b64decode(protocol_pubkey_b64, validate=True)
        pubkey = PublicKey(pubkey_bytes)
    except Exception as exc:  # noqa: BLE001 -- any malformed-key shape
        raise LLMKeyEncryptError(f"invalid protocol_pubkey_b64: {exc}") from exc

    box = SealedBox(pubkey)
    ciphertext = box.encrypt(raw_key.encode("utf-8"))
    return base64.b64encode(ciphertext).decode("ascii")
