"""Crypto primitives for the secure chat project."""

from .aes_gcm import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    DecryptionError,
    decrypt,
    encrypt,
    generate_key,
)

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "DecryptionError",
    "generate_key",
    "encrypt",
    "decrypt",
]
