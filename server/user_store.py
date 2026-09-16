"""Simple persistent user store, backed by a local JSON file.

Only the encoded PBKDF2 hash string from auth/password_hash.py is ever
written to disk -- plaintext passwords are never stored, logged, or printed.

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


def register_user(username: str, password: str, path: str = DEFAULT_STORE_PATH) -> bool:
    """Register a new user. Returns False if the username is already taken."""
    if not username or not password:
        return False
    with _lock:
        users = _load(path)
        if username in users:
            return False
        users[username] = {"password_hash": hash_password(password)}
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
