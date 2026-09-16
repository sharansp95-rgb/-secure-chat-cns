"""ECDH (X25519) key exchange for deriving per-session AES-256 keys.

Standard, well-vetted elliptic-curve Diffie-Hellman via the `cryptography`
library's X25519 implementation -- no hand-rolled modular exponentiation.

Each call to `generate_keypair()` must produce a *fresh* keypair: a new
keypair per chat session (per login / per peer), never reused across
sessions. This is what gives the scheme forward secrecy -- if a session key
is ever compromised, it reveals nothing about any other session, because
each session's private key existed only in memory for that session and is
discarded afterward.

Protocol (see README.md "How the handshake works" for the narrative version):
    1. Client A generates a keypair, sends A's public key bytes to Client B
       (relayed opaquely through the server).
    2. Client B generates its own keypair, sends B's public key bytes back.
    3. A computes compute_shared_key(A_private, B_public_bytes).
    4. B computes compute_shared_key(B_private, A_public_bytes).
    5. Both derive the identical 32-byte AES key -- the server never
       computes or observes the shared secret, only the opaque public keys.

The raw ECDH output is never used directly as an AES key: it is passed
through HKDF-SHA256 to produce a uniformly random 32-byte key, which is the
standard, correct way to turn a DH shared secret into symmetric key material.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["AES_KEY_SIZE", "generate_keypair", "compute_shared_key"]

AES_KEY_SIZE = 32  # AES-256

# Fixed, public, non-secret context info binding the derived key to this
# protocol. It does not need to be secret -- it just domain-separates this
# key derivation from any other use of HKDF elsewhere in the project.
_HKDF_INFO = b"CNSProject secure-chat ECDH session key v1"


def generate_keypair():
    """Generate a fresh X25519 keypair.

    Call this once per chat session / per peer -- never reuse a keypair
    across sessions. Returns (private_key, public_key_bytes):
      - private_key: an X25519PrivateKey object, kept in memory only, never
        sent anywhere.
      - public_key_bytes: 32 raw bytes, safe to send over the socket (and
        safe for the relay server to see -- it is public by design).
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def compute_shared_key(private_key, peer_public_key_bytes):
    """Compute the 32-byte AES session key shared with a peer.

    `private_key` is this side's own X25519PrivateKey from generate_keypair().
    `peer_public_key_bytes` is the 32 raw bytes the peer sent over the wire.

    Both sides of the handshake call this (each with their own private key
    and the other's public key bytes) and independently derive the same
    32-byte key -- that key is never itself transmitted.
    """
    if not isinstance(peer_public_key_bytes, (bytes, bytearray)):
        raise TypeError(
            "peer_public_key_bytes must be bytes, got "
            f"{type(peer_public_key_bytes).__name__}"
        )
    if len(peer_public_key_bytes) != 32:
        raise ValueError(
            f"X25519 public key must be exactly 32 bytes, got {len(peer_public_key_bytes)}"
        )

    peer_public_key = X25519PublicKey.from_public_bytes(bytes(peer_public_key_bytes))
    raw_shared_secret = private_key.exchange(peer_public_key)

    # Never use the raw ECDH output directly as an AES key -- run it through
    # HKDF-SHA256 to get a properly whitened, uniformly random 32-byte key.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=_HKDF_INFO,
    )
    return hkdf.derive(raw_shared_secret)
