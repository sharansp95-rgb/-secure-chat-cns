"""Local persistence for each user's long-term RSA identity keypair (Phase 5).

The private key never leaves the client -- only the public key (see
crypto_engine/signatures.py's serialize_public_key) is ever sent to the
server, at registration time, so other clients can fetch it to verify
signatures.

SIMPLIFICATION, NOT AN OVERSIGHT: in a real production system, the private
key file itself would be encrypted at rest -- typically wrapped under a key
derived from the user's login password (e.g. via the same PBKDF2 machinery
already used in auth/password_hash.py), so that anyone with filesystem
access to a stolen laptop still could not sign messages as that user without
also knowing their password. Here, for this course project, the private key
is written as a plain unencrypted PEM file under data/keys/ (itself
gitignored -- see .gitignore's `data/` entry) -- a deliberate scope
reduction to keep Phase 5 focused on the signing/verification mechanics
rather than key-wrapping, not something we didn't think about.
"""

import os

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from crypto_engine.signatures import deserialize_private_key, serialize_private_key

DEFAULT_KEYS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "keys"
)


def _private_key_path(username, keys_dir=DEFAULT_KEYS_DIR):
    return os.path.join(keys_dir, f"{username}_private.pem")


def save_private_key(username: str, private_key: RSAPrivateKey, keys_dir=DEFAULT_KEYS_DIR):
    """Write `private_key` to data/keys/<username>_private.pem as an
    unencrypted PEM file (see the module docstring for why that's an
    accepted simplification here)."""
    os.makedirs(keys_dir, exist_ok=True)
    path = _private_key_path(username, keys_dir)
    pem_bytes = serialize_private_key(private_key)  # no password -> NoEncryption
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(pem_bytes)
    os.replace(tmp_path, path)  # atomic on POSIX and Windows
    return path


def load_private_key(username: str, keys_dir=DEFAULT_KEYS_DIR):
    """Load the previously-saved private key for `username`, or None if this
    client has never generated/stored one for that username."""
    path = _private_key_path(username, keys_dir)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return deserialize_private_key(f.read())


def has_private_key(username: str, keys_dir=DEFAULT_KEYS_DIR) -> bool:
    return os.path.exists(_private_key_path(username, keys_dir))
