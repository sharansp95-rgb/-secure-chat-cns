"""Unit tests for the Phase 3 ECDH (X25519 + HKDF) key exchange."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_engine.aes_gcm import decrypt, encrypt  # noqa: E402
from crypto_engine.dh_exchange import (  # noqa: E402
    AES_KEY_SIZE,
    compute_shared_key,
    generate_keypair,
)


def test_both_sides_derive_the_identical_session_key():
    """Simulate Client A and Client B, each with their own keypair."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()

    key_a = compute_shared_key(priv_a, pub_b)
    key_b = compute_shared_key(priv_b, pub_a)

    assert key_a == key_b
    assert isinstance(key_a, bytes)
    assert len(key_a) == AES_KEY_SIZE == 32


def test_public_keys_are_32_raw_bytes():
    _, pub = generate_keypair()
    assert isinstance(pub, bytes)
    assert len(pub) == 32


def test_fresh_keypairs_produce_different_session_keys():
    """No key reuse across sessions -- forward secrecy requires this."""
    priv_a1, pub_a1 = generate_keypair()
    priv_b1, pub_b1 = generate_keypair()
    session_1 = compute_shared_key(priv_a1, pub_b1)

    # A brand new "session" (e.g. a reconnect) generates brand new keypairs.
    priv_a2, pub_a2 = generate_keypair()
    priv_b2, pub_b2 = generate_keypair()
    session_2 = compute_shared_key(priv_a2, pub_b2)

    assert session_1 != session_2


def test_different_keypair_generations_never_repeat():
    keys = set()
    for _ in range(20):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        keys.add(compute_shared_key(priv_a, pub_b))
    assert len(keys) == 20


def test_mismatched_pairing_yields_different_key():
    """A talking to C must not derive the same key as A talking to B."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    priv_c, pub_c = generate_keypair()

    key_ab = compute_shared_key(priv_a, pub_b)
    key_ac = compute_shared_key(priv_a, pub_c)
    assert key_ab != key_ac


def test_rejects_wrong_length_public_key():
    priv_a, _ = generate_keypair()
    with pytest.raises(ValueError):
        compute_shared_key(priv_a, b"too short")


def test_rejects_non_bytes_public_key():
    priv_a, _ = generate_keypair()
    with pytest.raises(TypeError):
        compute_shared_key(priv_a, "not bytes")


# --- integration with the Phase 2 AES-GCM engine ---------------------------

def test_derived_key_works_with_aes_gcm_round_trip():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    key_a = compute_shared_key(priv_a, pub_b)
    key_b = compute_shared_key(priv_b, pub_a)
    assert key_a == key_b

    plaintext = b"hello from the ECDH-derived session key"
    box = encrypt(key_a, plaintext)
    recovered = decrypt(key_b, box["nonce"], box["ciphertext"], box["tag"])
    assert recovered == plaintext


def test_derived_key_from_different_session_cannot_decrypt():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    key_ab = compute_shared_key(priv_a, pub_b)

    priv_c, pub_c = generate_keypair()
    key_ac = compute_shared_key(priv_a, pub_c)
    assert key_ab != key_ac

    box = encrypt(key_ab, b"secret for B only")
    from crypto_engine.aes_gcm import DecryptionError
    with pytest.raises(DecryptionError):
        decrypt(key_ac, box["nonce"], box["ciphertext"], box["tag"])
