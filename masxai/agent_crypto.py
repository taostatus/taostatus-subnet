from __future__ import annotations

"""Transport encryption for the security-track agent image.

The problem this solves: a security agent is shipped as a Docker image, and if
that image is public anyone -- including a competing miner -- can pull it and
read the agent's code. Encrypting the image so only the validator can decrypt it
at evaluation time keeps a miner's work private from its peers while still
letting the validator run it.

The shape mirrors the LLM-key track's `llm_key_crypto.py`, deliberately:

  * Miner side owns only `encrypt_agent()`. It has no keypair and never
    decrypts; its only identity is its Bittensor hotkey, already authenticated
    by the signed dendrite/axon exchange. NaCl SealedBox is exactly this case
    -- an anonymous sender encrypting to a recipient's public key.
  * Validator side owns the keypair and `decrypt_agent()`. Unlike the LLM-key
    backend, the validator DOES decrypt, because it must load and run the image.
    So this protects a miner from OTHER MINERS reading its code, not from the
    validator (which sees the plaintext image at run time by necessity).

What is encrypted is the raw bytes of a `docker save` tarball. SealedBox output
is non-deterministic (a fresh ephemeral key each time), so the ciphertext can
never be used to compare or dedupe two submissions -- exactly as with the
LLM-key blobs. Dedupe therefore happens after decryption, on the plaintext
tarball's sha256 and the loaded image's layer digest, where the existing
pipeline already does it.

MVP note: the whole tarball goes through SealedBox in one shot. That is fine for
the small agents we run today (a slim base plus a script). If images grow large,
switch to hybrid encryption -- a random SecretBox key encrypts the tarball, and
SealedBox encrypts only that key -- without changing this module's callers.
"""

import base64

from nacl.public import PrivateKey, PublicKey, SealedBox

BLOB_ENCODING = "nacl-sealedbox-v1"


class AgentCryptoError(ValueError):
    """Raised when a supplied key or ciphertext is malformed."""


def generate_keypair() -> tuple[str, str]:
    """Mint a fresh validator keypair.

    Returns (private_key_b64, public_key_b64). The validator persists the
    private half locally (like the rest of its state) and publishes the public
    half to miners in the ask synapse. Run once; reuse across restarts so that
    blobs a miner encrypted for a previous ask can still be decrypted.
    """
    sk = PrivateKey.generate()
    return (
        base64.b64encode(bytes(sk)).decode("ascii"),
        base64.b64encode(bytes(sk.public_key)).decode("ascii"),
    )


def public_key_b64(private_key_b64: str) -> str:
    """Derive the base64 public key from a stored base64 private key."""
    return base64.b64encode(bytes(_load_private(private_key_b64).public_key)).decode("ascii")


def encrypt_agent(tar_bytes: bytes, validator_pubkey_b64: str) -> bytes:
    """Miner side: encrypt a `docker save` tarball for the validator's pubkey.

    Returns raw ciphertext bytes, suitable for writing to a file the miner then
    hosts at a URL. Non-deterministic across calls, so callers must not expect a
    stable ciphertext hash for the same input.
    """
    if not isinstance(tar_bytes, (bytes, bytearray)):
        raise AgentCryptoError("tar_bytes must be bytes")
    try:
        pubkey = PublicKey(base64.b64decode(validator_pubkey_b64, validate=True))
    except Exception as exc:  # noqa: BLE001 -- any malformed-key shape
        raise AgentCryptoError(f"invalid validator_pubkey_b64: {exc}") from exc
    return bytes(SealedBox(pubkey).encrypt(bytes(tar_bytes)))


def decrypt_agent(blob: bytes, private_key_b64: str) -> bytes:
    """Validator side: recover the tarball bytes from a downloaded blob.

    Raises AgentCryptoError if the blob was not sealed for this key or is
    corrupt -- the caller treats that as a rejected submission, not a crash.
    """
    sk = _load_private(private_key_b64)
    try:
        return SealedBox(sk).decrypt(bytes(blob))
    except Exception as exc:  # noqa: BLE001 -- wrong key, truncated, tampered
        raise AgentCryptoError(f"decryption failed: {exc}") from exc


def _load_private(private_key_b64: str) -> PrivateKey:
    try:
        return PrivateKey(base64.b64decode(private_key_b64, validate=True))
    except Exception as exc:  # noqa: BLE001
        raise AgentCryptoError(f"invalid private_key_b64: {exc}") from exc
