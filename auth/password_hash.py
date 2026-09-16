"""PBKDF2-HMAC-SHA256 password hashing (Phase 4).

Passwords are never stored, logged, or printed in plaintext -- only the
encoded hash string produced by `hash_password()` is ever persisted (see
server/user_store.py).

Encoded format (a single self-describing string, so verification never needs
separate stored fields):

    pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>

- algorithm: fixed at "pbkdf2_sha256" (PBKDF2-HMAC-SHA256).
- iterations: deliberately slow, >= MIN_ITERATIONS, to resist brute force.
- salt: >= 16 random bytes, unique per password, base64-encoded.
- hash: the PBKDF2 derived key, base64-encoded.
"""

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
MIN_ITERATIONS = 200_000
SALT_SIZE = 16  # bytes
HASH_LEN = 32  # bytes (SHA-256 output size)


class InvalidHashFormat(Exception):
    """Raised when a stored hash string is malformed or uses an unknown algorithm."""


def hash_password(password: str, iterations: int = MIN_ITERATIONS) -> str:
    """Hash `password` with PBKDF2-HMAC-SHA256 under a fresh random salt.

    Returns a single encoded string: "pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>".
    The plaintext password is used only in memory for this computation and is
    never itself written to the returned string, a file, or a log.
    """
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations must be >= {MIN_ITERATIONS}, got {iterations}")

    salt = secrets.token_bytes(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=HASH_LEN
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"{ALGORITHM}${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    """Recompute the hash of `password` with the salt/iterations from `stored`
    and compare against the stored hash in constant time.

    Returns False (never raises) for a wrong password. Raises
    `InvalidHashFormat` only if `stored` itself is malformed -- that is a
    data-integrity problem, not a "wrong password" outcome.
    """
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")

    try:
        algorithm, iterations_str, salt_b64, hash_b64 = stored.split("$")
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError) as exc:
        raise InvalidHashFormat(f"malformed stored hash: {stored!r}") from exc

    if algorithm != ALGORITHM:
        raise InvalidHashFormat(f"unsupported algorithm: {algorithm!r}")

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    # Constant-time comparison -- never use `==` here, which short-circuits on
    # the first mismatched byte and can leak timing information.
    return hmac.compare_digest(candidate, expected)
