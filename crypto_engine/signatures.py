"""RSA-2048 digital signatures for non-repudiation (Phase 5).

Distinct from the Phase 3 ECDH keys: an ECDH session key only proves
"whoever holds this session key sent this" -- it says nothing about *which*
long-term identity that was, and a session key is symmetric, so either side
could have produced any message under it (no third party could ever be
convinced who actually wrote it). An RSA signature, by contrast, can only be
produced by the holder of one specific private key, and can be checked by
anyone holding the matching public key -- that is what makes it possible to
prove authorship after the fact (non-repudiation).

Uses the `cryptography` library's RSA implementation, not hand-rolled RSA.

Padding: RSA-PSS (Probabilistic Signature Scheme), not the older PKCS#1 v1.5.
PSS is the modern recommended choice for new signature schemes -- it has a
security proof reducing to the RSA problem, and (being randomized per
signature) two signatures of the same message look different, unlike
deterministic PKCS#1 v1.5. There's no compatibility reason here to prefer
the older scheme, so PSS is used throughout.

Hash: SHA-256, matching the aes_gcm/dh_exchange modules elsewhere in this
project.
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

__all__ = [
    "KEY_SIZE",
    "generate_keypair",
    "sign",
    "verify",
    "serialize_private_key",
    "deserialize_private_key",
    "serialize_public_key",
    "deserialize_public_key",
    "fingerprint",
]

KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537  # standard choice; small, known-safe exponent


def generate_keypair():
    """Generate a fresh RSA-2048 private/public keypair.

    Returns (private_key, public_key) as cryptography library key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=_PUBLIC_EXPONENT, key_size=KEY_SIZE
    )
    return private_key, private_key.public_key()


def _pss_padding():
    # MAX_LENGTH is the conventional salt-length choice for PSS; matches the
    # digest size and is what OpenSSL/most libraries default to.
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def sign(private_key, message: bytes) -> bytes:
    """Sign `message` (SHA-256 + RSA-PSS) with `private_key`.

    Returns the raw signature bytes.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    return private_key.sign(bytes(message), _pss_padding(), hashes.SHA256())


def verify(public_key, message: bytes, signature: bytes) -> bool:
    """Verify `signature` over `message` under `public_key`.

    Returns True/False -- never raises for a bad, tampered, or
    wrong-key signature. Callers can treat False as an ordinary rejection.
    """
    if not isinstance(message, (bytes, bytearray)) or not isinstance(
        signature, (bytes, bytearray)
    ):
        return False
    try:
        public_key.verify(bytes(signature), bytes(message), _pss_padding(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        # Malformed signature bytes, mismatched key size, etc. -- still just
        # a rejection, not a crash.
        return False


# --- PEM serialization -----------------------------------------------------
# Private keys move between memory and a local file (auth/keystore.py).
# Public keys additionally move over the wire (get_pubkey envelopes), so both
# need clean bytes <-> key-object conversions.

def serialize_private_key(private_key, password: bytes = None) -> bytes:
    """Encode a private key as PEM. If `password` is given, the PEM is
    encrypted with it; otherwise it is written unencrypted (see the
    at-rest-encryption note in auth/keystore.py)."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def deserialize_private_key(pem_bytes: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


# --- fingerprint (Phase 7: human-verifiable MITM check) --------------------

def fingerprint(public_key_pem: bytes, length: int = 16) -> str:
    """Return a short, human-readable fingerprint of an RSA public key: the
    first `length` hex characters of SHA-256(PEM bytes), grouped in 4-char
    blocks (e.g. "A1B2 C3D4 E5F6 A7B8").

    This is what two humans read out to each other (e.g. over a voice call)
    to independently confirm they hold the same public key for a given
    identity -- a check that doesn't depend on trusting the relay server or
    the software's own automated verification, which is exactly the point:
    it catches a MITM even if it somehow fooled every automated check.

    Both sides must fingerprint the *same* canonical bytes to get matching
    results, so callers should always pass the exact PEM bytes as received
    (e.g. from a get_pubkey response), not a re-serialization that might
    differ in whitespace/line-ending details.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    digest = hashlib.sha256(public_key_pem).hexdigest().upper()[:length]
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
