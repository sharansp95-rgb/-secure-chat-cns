"""Unit tests for the Phase 5 RSA-2048 (RSA-PSS + SHA-256) signatures."""

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_engine.aes_gcm import DecryptionError, decrypt, encrypt  # noqa: E402
from crypto_engine.dh_exchange import compute_shared_key  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import (  # noqa: E402
    KEY_SIZE,
    deserialize_private_key,
    deserialize_public_key,
    generate_keypair,
    serialize_private_key,
    serialize_public_key,
    sign,
    verify,
)


def test_round_trip_correct_signature_verifies():
    private_key, public_key = generate_keypair()
    message = b"transfer 100 rupees to alice"
    signature = sign(private_key, message)
    assert verify(public_key, message, signature) is True


def test_tampered_message_fails_verification():
    private_key, public_key = generate_keypair()
    message = bytearray(b"transfer 100 rupees to alice")
    signature = sign(private_key, bytes(message))

    tampered = bytearray(message)
    tampered[0] ^= 0x01
    assert verify(public_key, bytes(tampered), signature) is False


def test_wrong_public_key_fails_verification():
    private_key_a, _ = generate_keypair()
    _, public_key_b = generate_keypair()
    message = b"only alice should be able to sign this"
    signature = sign(private_key_a, message)

    assert verify(public_key_b, message, signature) is False


def test_corrupted_signature_fails_verification():
    private_key, public_key = generate_keypair()
    message = b"integrity of the signature itself matters too"
    signature = bytearray(sign(private_key, message))
    signature[-1] ^= 0xFF

    assert verify(public_key, message, bytes(signature)) is False


def test_verify_never_raises_on_garbage_signature():
    _, public_key = generate_keypair()
    assert verify(public_key, b"hello", b"not a real signature at all") is False
    assert verify(public_key, b"hello", b"") is False


def test_keypair_is_rsa_2048():
    private_key, public_key = generate_keypair()
    assert private_key.key_size == KEY_SIZE == 2048
    assert public_key.key_size == KEY_SIZE == 2048


def test_two_signatures_of_same_message_differ():
    """RSA-PSS is randomized (unlike PKCS#1 v1.5), so two signatures of the
    same message under the same key should not be byte-identical."""
    private_key, public_key = generate_keypair()
    message = b"same message signed twice"
    sig1 = sign(private_key, message)
    sig2 = sign(private_key, message)
    assert sig1 != sig2
    assert verify(public_key, message, sig1)
    assert verify(public_key, message, sig2)


# --- PEM serialization -----------------------------------------------------

def test_private_key_pem_round_trip():
    private_key, public_key = generate_keypair()
    pem = serialize_private_key(private_key)
    assert b"PRIVATE KEY" in pem
    restored = deserialize_private_key(pem)
    message = b"pem round trip check"
    assert verify(public_key, message, sign(restored, message))


def test_public_key_pem_round_trip():
    private_key, public_key = generate_keypair()
    pem = serialize_public_key(public_key)
    assert b"PUBLIC KEY" in pem
    restored = deserialize_public_key(pem)
    message = b"pem round trip check for public key"
    signature = sign(private_key, message)
    assert verify(restored, message, signature)


def test_private_key_pem_does_not_leak_as_public():
    private_key, _ = generate_keypair()
    pem = serialize_private_key(private_key)
    assert b"-----BEGIN PRIVATE KEY-----" in pem
    assert b"-----BEGIN PUBLIC KEY-----" not in pem


# --- full pipeline integration: sign -> wrap -> AES-GCM encrypt -> decrypt
# -> verify, simulating the real client.py sign-then-encrypt flow -----------

def test_full_pipeline_sign_encrypt_decrypt_verify():
    # Simulate two identities, A (sender) and B (receiver).
    rsa_priv_a, rsa_pub_a = generate_keypair()

    # Simulate the Phase 3 ECDH handshake deriving A and B's shared AES key.
    ecdh_priv_a, ecdh_pub_a = generate_ecdh_keypair()
    ecdh_priv_b, ecdh_pub_b = generate_ecdh_keypair()
    session_key_a = compute_shared_key(ecdh_priv_a, ecdh_pub_b)
    session_key_b = compute_shared_key(ecdh_priv_b, ecdh_pub_a)
    assert session_key_a == session_key_b

    # A signs the plaintext with its own RSA key, wraps {message, signature},
    # then AES-GCM encrypts the wrapped payload with the shared session key
    # -- exactly the order client.py uses.
    message = "hello B, this is really A"
    signature = sign(rsa_priv_a, message.encode("utf-8"))
    import json
    wrapped = json.dumps({
        "message": message,
        "signature": base64.b64encode(signature).decode("ascii"),
    }).encode("utf-8")
    box = encrypt(session_key_a, wrapped)

    # B decrypts with its independently-derived session key, unwraps, and
    # verifies against A's public key (which B would have fetched via
    # get_pubkey in the real client).
    decrypted = decrypt(session_key_b, box["nonce"], box["ciphertext"], box["tag"])
    inner = json.loads(decrypted.decode("utf-8"))
    recovered_message = inner["message"]
    recovered_signature = base64.b64decode(inner["signature"])

    assert recovered_message == message
    assert verify(rsa_pub_a, recovered_message.encode("utf-8"), recovered_signature)


def test_full_pipeline_catches_tampering_anywhere_in_the_chain():
    rsa_priv_a, rsa_pub_a = generate_keypair()
    ecdh_priv_a, ecdh_pub_a = generate_ecdh_keypair()
    ecdh_priv_b, ecdh_pub_b = generate_ecdh_keypair()
    session_key_a = compute_shared_key(ecdh_priv_a, ecdh_pub_b)
    session_key_b = compute_shared_key(ecdh_priv_b, ecdh_pub_a)

    import json
    message = "the real message"
    signature = sign(rsa_priv_a, message.encode("utf-8"))
    wrapped = json.dumps({
        "message": message,
        "signature": base64.b64encode(signature).decode("ascii"),
    }).encode("utf-8")
    box = encrypt(session_key_a, wrapped)

    # 1) Tamper with the ciphertext -> AES-GCM itself must catch this.
    tampered_ct = bytearray(box["ciphertext"])
    tampered_ct[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt(session_key_b, box["nonce"], bytes(tampered_ct), box["tag"])

    # 2) An attacker who also controlled a *different* session key entirely
    #    (e.g. a MITM impersonation attempt) cannot forge a valid ciphertext
    #    for B's real session key.
    other_priv, other_pub = generate_ecdh_keypair()
    forged_session_key = compute_shared_key(other_priv, ecdh_pub_b)
    assert forged_session_key != session_key_a
    forged_box = encrypt(forged_session_key, wrapped)
    with pytest.raises(DecryptionError):
        decrypt(session_key_b, forged_box["nonce"], forged_box["ciphertext"], box["tag"])

    # 3) Even if decryption succeeds (correct session key) but the signature
    #    itself was forged/tampered, verification must fail.
    decrypted = decrypt(session_key_b, box["nonce"], box["ciphertext"], box["tag"])
    inner = json.loads(decrypted.decode("utf-8"))
    forged_signature = bytearray(base64.b64decode(inner["signature"]))
    forged_signature[-1] ^= 0xFF
    assert verify(rsa_pub_a, inner["message"].encode("utf-8"), bytes(forged_signature)) is False
