"""Tests for masxai/agent_crypto.py -- the security-track agent encryption.

The scheme is public (Kerckhoffs); only the validator's private key is secret.
So these tests live in the public suite: they prove the roundtrip works and,
more importantly, that a blob leaks nothing to anyone without the private key.
"""

import pytest

from masxai import agent_crypto as ac


def test_roundtrip_recovers_exact_bytes():
    priv, pub = ac.generate_keypair()
    data = b"FAKE_DOCKER_SAVE_TARBALL" * 1000
    blob = ac.encrypt_agent(data, pub)
    assert ac.decrypt_agent(blob, priv) == data


def test_ciphertext_is_non_deterministic():
    # A peer must not be able to tell two submissions apart by their blobs,
    # so the same plaintext must never produce the same ciphertext twice.
    priv, pub = ac.generate_keypair()
    data = b"same input"
    assert ac.encrypt_agent(data, pub) != ac.encrypt_agent(data, pub)


def test_wrong_private_key_cannot_decrypt():
    _, pub = ac.generate_keypair()
    other_priv, _ = ac.generate_keypair()
    blob = ac.encrypt_agent(b"secret agent", pub)
    with pytest.raises(ac.AgentCryptoError):
        ac.decrypt_agent(blob, other_priv)


def test_tampered_blob_is_rejected():
    priv, pub = ac.generate_keypair()
    blob = bytearray(ac.encrypt_agent(b"secret agent", pub))
    blob[-1] ^= 0xFF  # flip a bit
    with pytest.raises(ac.AgentCryptoError):
        ac.decrypt_agent(bytes(blob), priv)


def test_public_key_derives_from_private():
    priv, pub = ac.generate_keypair()
    assert ac.public_key_b64(priv) == pub


@pytest.mark.parametrize("bad", ["not-base64!!", "", "YWJj"])  # last is valid b64 but wrong length
def test_malformed_pubkey_rejected(bad):
    with pytest.raises(ac.AgentCryptoError):
        ac.encrypt_agent(b"data", bad)


def test_non_bytes_plaintext_rejected():
    _, pub = ac.generate_keypair()
    with pytest.raises(ac.AgentCryptoError):
        ac.encrypt_agent("a string, not bytes", pub)  # type: ignore[arg-type]
