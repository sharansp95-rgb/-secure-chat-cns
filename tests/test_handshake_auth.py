"""Tests for Phase 7a: signing the ECDH handshake to close the MITM gap.

Exercises the real SecureChatClient handshake methods directly (not through
sockets) -- these are pure state-machine methods that only touch attributes
set up here, so this is a fast, deterministic way to verify the actual
production code path rather than reimplementing its logic in the test.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import SecureChatClient, b64  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import (  # noqa: E402
    fingerprint,
    generate_keypair,
    serialize_public_key,
)


class FakeSocket:
    """Minimal stand-in for a real socket: records what was sent, does
    nothing on receipt (these tests drive the client's handlers directly)."""

    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def last_envelope(self):
        return json.loads(self.sent[-1].decode("utf-8"))


def make_client(username, peer, rsa_private_key=None, peer_public_key=None,
                 peer_public_key_pem=None):
    client = SecureChatClient(FakeSocket(), username, peer)
    client.rsa_private_key = rsa_private_key
    client.peer_public_key = peer_public_key
    client.peer_public_key_pem = peer_public_key_pem
    return client


@pytest.fixture()
def identities():
    """Two real identities, A and B, each with their own RSA keypair, each
    already knowing the other's public key -- the state a real client would
    be in right after a successful get_pubkey fetch."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    pem_a = serialize_public_key(pub_a).decode("ascii")
    pem_b = serialize_public_key(pub_b).decode("ascii")
    return {
        "priv_a": priv_a, "pub_a": pub_a, "pem_a": pem_a,
        "priv_b": priv_b, "pub_b": pub_b, "pem_b": pem_b,
    }


# --- 1. a correctly signed handshake completes normally -------------------

def test_correctly_signed_handshake_completes(identities):
    a = make_client("alice", "bob", identities["priv_a"], identities["pub_b"], identities["pem_b"])
    b = make_client("bob", "alice", identities["priv_b"], identities["pub_a"], identities["pem_a"])

    a.initiate_handshake()
    handshake_init = a.sock.last_envelope()
    assert handshake_init["type"] == "handshake_init"
    assert "handshake_sig" in handshake_init

    b._handle_handshake_init(handshake_init)
    assert b.session_key is not None

    handshake_response = b.sock.last_envelope()
    assert handshake_response["type"] == "handshake_response"
    assert "handshake_sig" in handshake_response

    a._handle_handshake_response(handshake_response)
    assert a.session_key is not None
    assert a.session_key == b.session_key


# --- 2. the ECDH public key is swapped/tampered after signing -------------

def test_tampered_ecdh_pubkey_after_signing_is_rejected(identities):
    a = make_client("alice", "bob", identities["priv_a"], identities["pub_b"], identities["pem_b"])
    b = make_client("bob", "alice", identities["priv_b"], identities["pub_a"], identities["pem_a"])

    a.initiate_handshake()
    handshake_init = a.sock.last_envelope()

    # Swap in a different ECDH public key after A signed the original one --
    # the signature no longer matches this substituted key.
    _, swapped_ecdh_pub = generate_ecdh_keypair()
    tampered = dict(handshake_init)
    tampered["pubkey"] = b64(swapped_ecdh_pub)

    b._handle_handshake_init(tampered)
    assert b.session_key is None, "tampered handshake must not yield a session key"
    # B must not have replied with a handshake_response to a rejected handshake.
    assert b.sock.sent == []


def test_tampered_handshake_response_is_rejected(identities):
    a = make_client("alice", "bob", identities["priv_a"], identities["pub_b"], identities["pem_b"])
    b = make_client("bob", "alice", identities["priv_b"], identities["pub_a"], identities["pem_a"])

    a.initiate_handshake()
    b._handle_handshake_init(a.sock.last_envelope())
    handshake_response = b.sock.last_envelope()

    _, swapped_ecdh_pub = generate_ecdh_keypair()
    tampered = dict(handshake_response)
    tampered["pubkey"] = b64(swapped_ecdh_pub)

    a._handle_handshake_response(tampered)
    assert a.session_key is None, "tampered handshake_response must not yield a session key"


# --- 3. a handshake signed with the wrong RSA private key is rejected -----

def test_handshake_signed_with_wrong_key_is_rejected(identities):
    """Simulates impersonation: 'mallory' signs a handshake_init claiming to
    be from 'alice', using mallory's own RSA key instead of alice's."""
    priv_mallory, _ = generate_keypair()

    # Attacker-controlled client, but claiming the "alice" identity.
    mallory_as_alice = make_client(
        "alice", "bob", rsa_private_key=priv_mallory, peer_public_key=identities["pub_b"],
    )
    mallory_as_alice.initiate_handshake()
    forged_handshake_init = mallory_as_alice.sock.last_envelope()

    # Bob trusts the REAL alice's RSA public key (fetched via get_pubkey
    # earlier, e.g. at session start) -- not mallory's.
    b = make_client("bob", "alice", identities["priv_b"], identities["pub_a"], identities["pem_a"])
    b._handle_handshake_init(forged_handshake_init)

    assert b.session_key is None, "impersonated handshake must be rejected"
    assert b.sock.sent == []


def test_handshake_with_no_signature_at_all_is_rejected(identities):
    a = make_client("alice", "bob", rsa_private_key=None, peer_public_key=identities["pub_b"])
    a.initiate_handshake()  # no RSA key -> sends an empty signature
    handshake_init = a.sock.last_envelope()
    assert handshake_init["handshake_sig"] == b64(b"")

    b = make_client("bob", "alice", identities["priv_b"], identities["pub_a"], identities["pem_a"])
    b._handle_handshake_init(handshake_init)
    assert b.session_key is None


def test_handshake_aborted_when_peer_public_key_unknown(identities):
    """Fail-closed: if we haven't fetched the peer's RSA public key yet, we
    cannot verify their handshake signature, so we must not derive a session
    key -- not silently trust the handshake."""
    a = make_client("alice", "bob", identities["priv_a"], identities["pub_b"], identities["pem_b"])
    a.initiate_handshake()
    handshake_init = a.sock.last_envelope()

    b = make_client("bob", "alice", identities["priv_b"], peer_public_key=None)
    b._handle_handshake_init(handshake_init)
    assert b.session_key is None


# --- 4. fingerprints match for the same key, differ for different keys ----

def test_fingerprint_matches_for_same_public_key(identities):
    fp1 = fingerprint(identities["pem_a"])
    fp2 = fingerprint(identities["pem_a"])
    assert fp1 == fp2


def test_fingerprint_differs_for_different_public_keys(identities):
    fp_a = fingerprint(identities["pem_a"])
    fp_b = fingerprint(identities["pem_b"])
    assert fp_a != fp_b


def test_both_sides_compute_the_same_fingerprint_for_each_other(identities):
    """What two humans would read aloud to compare: A's view of B's
    fingerprint must equal what B would compute for their own key."""
    fp_seen_by_a = fingerprint(identities["pem_b"])
    fp_computed_by_b_for_self = fingerprint(
        serialize_public_key(identities["priv_b"].public_key())
    )
    assert fp_seen_by_a == fp_computed_by_b_for_self
