"""Unit tests for the Phase 2 AES-256-GCM engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_engine import (  # noqa: E402
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    DecryptionError,
    decrypt,
    encrypt,
    generate_key,
)


# --- key generation -------------------------------------------------------

def test_generate_key_is_32_bytes():
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == KEY_SIZE == 32


def test_generate_key_is_not_deterministic():
    assert generate_key() != generate_key()


# --- round trip -----------------------------------------------------------

@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b"hello team 15, this is a normal message", id="normal"),
        pytest.param(b"", id="empty"),
        pytest.param("café ☕ 你好 🔐 émoji".encode("utf-8"), id="unicode-emoji"),
        pytest.param(b"x" * 10000, id="large"),
    ],
)
def test_round_trip(plaintext):
    key = generate_key()
    box = encrypt(key, plaintext)
    assert decrypt(key, box["nonce"], box["ciphertext"], box["tag"]) == plaintext


def test_encrypt_returns_expected_shape():
    box = encrypt(generate_key(), b"shape check")
    assert set(box) == {"nonce", "ciphertext", "tag"}
    assert len(box["nonce"]) == NONCE_SIZE == 12
    assert len(box["tag"]) == TAG_SIZE == 16


def test_ciphertext_is_not_plaintext():
    plaintext = b"this must not appear on the wire"
    box = encrypt(generate_key(), plaintext)
    assert box["ciphertext"] != plaintext
    assert plaintext not in box["ciphertext"]


# --- tampering ------------------------------------------------------------

def test_tampered_ciphertext_is_rejected():
    key = generate_key()
    box = encrypt(key, b"transfer 100 rupees to alice")

    flipped = bytearray(box["ciphertext"])
    flipped[0] ^= 0x01  # flip a single bit of one byte
    tampered = bytes(flipped)
    assert tampered != box["ciphertext"]

    with pytest.raises(DecryptionError):
        decrypt(key, box["nonce"], tampered, box["tag"])


def test_tampered_tag_is_rejected():
    key = generate_key()
    box = encrypt(key, b"integrity matters")
    bad_tag = bytearray(box["tag"])
    bad_tag[-1] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt(key, box["nonce"], box["ciphertext"], bytes(bad_tag))


def test_tampered_nonce_is_rejected():
    key = generate_key()
    box = encrypt(key, b"nonce binding")
    bad_nonce = bytearray(box["nonce"])
    bad_nonce[0] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt(key, bytes(bad_nonce), box["ciphertext"], box["tag"])


# --- wrong key ------------------------------------------------------------

def test_wrong_key_is_rejected():
    key = generate_key()
    other_key = generate_key()
    assert key != other_key

    box = encrypt(key, b"secret only alice and bob share")
    with pytest.raises(DecryptionError):
        decrypt(other_key, box["nonce"], box["ciphertext"], box["tag"])


def test_wrong_key_never_returns_plaintext():
    """A failed decrypt must raise, not hand back garbage that looks like data."""
    key, other_key = generate_key(), generate_key()
    plaintext = b"top secret"
    box = encrypt(key, plaintext)

    result = None
    try:
        result = decrypt(other_key, box["nonce"], box["ciphertext"], box["tag"])
    except DecryptionError:
        pass
    assert result is None, "decrypt returned data under the wrong key"


# --- nonce hygiene --------------------------------------------------------

def test_nonces_differ_across_calls_with_same_key_and_plaintext():
    key = generate_key()
    plaintext = b"identical message"
    first = encrypt(key, plaintext)
    second = encrypt(key, plaintext)

    assert first["nonce"] != second["nonce"], "nonce reuse would break GCM"
    assert first["ciphertext"] != second["ciphertext"], (
        "same key + same plaintext must not produce identical ciphertext"
    )


def test_nonces_are_unique_over_many_calls():
    key = generate_key()
    nonces = {encrypt(key, b"repeat")["nonce"] for _ in range(500)}
    assert len(nonces) == 500


# --- input validation -----------------------------------------------------

def test_short_key_rejected():
    with pytest.raises(ValueError):
        encrypt(b"too short", b"data")


def test_str_plaintext_rejected():
    with pytest.raises(TypeError):
        encrypt(generate_key(), "not bytes")
