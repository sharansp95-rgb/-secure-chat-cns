"""AES-256-GCM authenticated encryption for the secure chat project.

Standalone Phase 2 module: it is not yet wired into the live chat, because the
session key it consumes will come from the Diffie-Hellman exchange in Phase 3.
Until then `generate_key()` supplies keys for tests and experiments.

GCM gives us confidentiality *and* integrity in one pass. The authentication tag
is verified on every decrypt, so a tampered ciphertext or a wrong key raises
`DecryptionError` instead of returning plausible-looking garbage.

Interface
---------
`encrypt(key, plaintext)` returns a dict with exactly three keys::

    {"nonce": bytes(12), "ciphertext": bytes, "tag": bytes(16)}

`decrypt(key, nonce, ciphertext, tag)` takes those three values back as separate
arguments and returns the original plaintext bytes. The dict can therefore be
splatted straight back in::

    box = encrypt(key, b"hi")
    assert decrypt(key, **box) == b"hi"
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "DecryptionError",
    "generate_key",
    "encrypt",
    "decrypt",
]

KEY_SIZE = 32   # AES-256
NONCE_SIZE = 12  # 96-bit nonce, the size GCM is designed around
TAG_SIZE = 16


class DecryptionError(Exception):
    """Authentication failed: the ciphertext was tampered with, or the key,
    nonce, or tag is wrong. The plaintext is never returned in this case."""


def generate_key():
    """Return a fresh random 32-byte (AES-256) key.

    Placeholder for Phase 3, where the key becomes a Diffie-Hellman shared
    secret rather than a locally generated random value.
    """
    return get_random_bytes(KEY_SIZE)


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes, got {type(key).__name__}")
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be exactly {KEY_SIZE} bytes, got {len(key)}")


def encrypt(key, plaintext):
    """Encrypt `plaintext` under `key` with AES-256-GCM.

    A fresh random 12-byte nonce is generated on every call -- reusing a nonce
    with the same key would break GCM catastrophically, so callers are never
    allowed to supply one.

    Returns {"nonce": bytes, "ciphertext": bytes, "tag": bytes}.
    """
    _check_key(key)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(
            f"plaintext must be bytes, got {type(plaintext).__name__} "
            "(encode str with .encode('utf-8') first)"
        )

    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}


def decrypt(key, nonce, ciphertext, tag):
    """Verify and decrypt, returning the original plaintext bytes.

    Raises `DecryptionError` if the tag does not verify -- tampering is rejected,
    never silently accepted.
    """
    _check_key(key)
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be exactly {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(tag) != TAG_SIZE:
        raise ValueError(f"tag must be exactly {TAG_SIZE} bytes, got {len(tag)}")

    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce), mac_len=TAG_SIZE)
    try:
        return cipher.decrypt_and_verify(bytes(ciphertext), bytes(tag))
    except ValueError as exc:
        # PyCryptodome raises a bare ValueError("MAC check failed"); re-raise as
        # our own specific type so callers cannot confuse it with a bad argument.
        raise DecryptionError(
            "authentication failed: message was tampered with or the key is wrong"
        ) from exc
