"""Simple persistent user store, backed by a local JSON file.

Only the encoded PBKDF2 hash string from auth/password_hash.py is ever
written to disk for a password -- plaintext passwords are never stored,
logged, or printed.

Phase 5 adds each user's long-term RSA *public* key (PEM text) alongside
their password hash. Unlike the password hash, a public key is not sensitive
-- by design, it is meant to be handed out to anyone who needs to verify
that user's signatures (see crypto_engine/signatures.py, server.py's
"get_pubkey" envelope). The matching private key never reaches the server;
it stays on the owning client (see auth/keystore.py).

The store file lives under data/ (gitignored -- see .gitignore), since it
holds real hashed credentials from local testing and has no business in
shared repo history.
"""

import json
import os
import threading

from auth.password_hash import hash_password, verify_password

DEFAULT_STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "users.json"
)

# Guards read-modify-write of the store file against concurrent client
# threads racing to register/login at the same time.
_lock = threading.Lock()


def _load(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save(path, users):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp_path, path)  # atomic on POSIX and Windows


def register_user(
    username: str,
    password: str,
    public_key_pem: str = None,
    path: str = DEFAULT_STORE_PATH,
) -> bool:
    """Register a new user. Returns False if the username is already taken.

    `public_key_pem` is the user's RSA public key (PEM text, from
    crypto_engine.signatures.serialize_public_key(...).decode()) -- optional
    at the storage layer so existing tests/callers that only care about
    passwords keep working, but client.py always supplies one in practice.
    """
    if not username or not password:
        return False
    with _lock:
        users = _load(path)
        if username in users:
            return False
        record = {"password_hash": hash_password(password)}
        if public_key_pem:
            record["public_key"] = public_key_pem
        users[username] = record
        _save(path, users)
    return True


def verify_user(username: str, password: str, path: str = DEFAULT_STORE_PATH) -> bool:
    """Check a username/password pair against the store. Returns False for an
    unknown username or a wrong password -- never raises for bad credentials."""
    with _lock:
        users = _load(path)
    record = users.get(username)
    if record is None:
        return False
    try:
        return verify_password(password, record["password_hash"])
    except Exception:
        # Malformed stored hash or similar data problem: treat as auth
        # failure rather than crashing the server.
        return False


def user_exists(username: str, path: str = DEFAULT_STORE_PATH) -> bool:
    with _lock:
        users = _load(path)
    return username in users


def get_public_key(username: str, path: str = DEFAULT_STORE_PATH):
    """Return the stored RSA public key PEM (str) for `username`, or None if
    the user doesn't exist or never registered one (e.g. an account created
    before Phase 5)."""
    with _lock:
        users = _load(path)
    record = users.get(username)
    if record is None:
        return None
    return record.get("public_key")
