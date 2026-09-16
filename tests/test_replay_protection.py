"""Tests for Phase 7b: replay protection on chat messages.

A captured, validly-encrypted, validly-signed chat envelope must not be
accepted again later (or twice) just because AES-GCM and the RSA signature
both check out -- neither of those checks anything about *when* the message
is being presented. Two independent defenses are tested here:
  1. A timestamp, covered by the RSA signature, checked against a freshness
     window on receipt.
  2. Exact-repeat (same sender, same AES-GCM nonce) detection in memory,
     belt-and-suspenders against a message replayed within the window.
"""

import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import (  # noqa: E402
    CLOCK_SKEW_SECONDS,
    REPLAY_WINDOW_SECONDS,
    SecureChatClient,
    b64,
    chat_signable_bytes,
    is_timestamp_fresh,
)
from crypto_engine.aes_gcm import encrypt, generate_key  # noqa: E402
from crypto_engine.signatures import generate_keypair, sign  # noqa: E402


class FakeSocket:
    def sendall(self, data):
        pass


def build_chat_envelope(sender_name, rsa_private_key, session_key, text, timestamp):
    """Build a real, validly-encrypted, validly-signed chat envelope exactly
    the way SecureChatClient._encrypt_and_send does, so these tests exercise
    the real receive-side logic against realistic input."""
    signable = chat_signable_bytes(text, timestamp)
    signature = sign(rsa_private_key, signable)
    inner = json.dumps({
        "message": text, "timestamp": timestamp, "signature": b64(signature),
    }).encode("utf-8")
    box = encrypt(session_key, inner)
    return {
        "type": "chat", "from": sender_name,
        "nonce": b64(box["nonce"]), "ciphertext": b64(box["ciphertext"]), "tag": b64(box["tag"]),
    }


@pytest.fixture()
def receiver():
    """A client with an established session, ready to receive from 'alice'."""
    priv_a, pub_a = generate_keypair()
    session_key = generate_key()
    client = SecureChatClient(FakeSocket(), "bob", "alice")
    client.session_key = session_key
    client.peer_public_key = pub_a
    return client, priv_a, session_key


def _receive_and_capture(client, envelope, monkeypatch):
    outputs = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: outputs.append(" ".join(str(x) for x in a)))
    client._handle_chat(envelope)
    return "\n".join(outputs)


# --- is_timestamp_fresh() unit checks --------------------------------------

def test_is_timestamp_fresh_accepts_current_time():
    assert is_timestamp_fresh(time.time()) is True


def test_is_timestamp_fresh_rejects_stale():
    assert is_timestamp_fresh(time.time() - REPLAY_WINDOW_SECONDS - 1) is False


def test_is_timestamp_fresh_rejects_far_future():
    assert is_timestamp_fresh(time.time() + CLOCK_SKEW_SECONDS + 1) is False


def test_is_timestamp_fresh_accepts_small_clock_skew():
    assert is_timestamp_fresh(time.time() + CLOCK_SKEW_SECONDS - 1) is True


# --- full receive-path checks ----------------------------------------------

def test_fresh_message_is_accepted(receiver, monkeypatch):
    client, priv_a, session_key = receiver
    envelope = build_chat_envelope("alice", priv_a, session_key, "hello bob", int(time.time()))
    output = _receive_and_capture(client, envelope, monkeypatch)
    assert "alice: hello bob" in output


def test_stale_timestamp_is_rejected(receiver, monkeypatch):
    client, priv_a, session_key = receiver
    old_timestamp = int(time.time()) - REPLAY_WINDOW_SECONDS - 10
    envelope = build_chat_envelope("alice", priv_a, session_key, "old message", old_timestamp)
    output = _receive_and_capture(client, envelope, monkeypatch)
    assert "old message" not in output
    assert "stale or future timestamp" in output


def test_future_timestamp_beyond_skew_is_rejected(receiver, monkeypatch):
    client, priv_a, session_key = receiver
    future_timestamp = int(time.time()) + CLOCK_SKEW_SECONDS + 20
    envelope = build_chat_envelope("alice", priv_a, session_key, "from the future", future_timestamp)
    output = _receive_and_capture(client, envelope, monkeypatch)
    assert "from the future" not in output
    assert "stale or future timestamp" in output


def test_replayed_envelope_is_rejected_on_second_delivery(receiver, monkeypatch):
    client, priv_a, session_key = receiver
    envelope = build_chat_envelope("alice", priv_a, session_key, "pay mallory 100 btc",
                                    int(time.time()))

    first = _receive_and_capture(client, envelope, monkeypatch)
    assert "pay mallory 100 btc" in first

    # Exact same envelope, resent verbatim (as a captured-and-replayed
    # attacker would send it) -- must be rejected the second time even
    # though its timestamp is still within the freshness window.
    second = _receive_and_capture(client, dict(envelope), monkeypatch)
    assert "pay mallory 100 btc" not in second
    assert "replay" in second.lower()


def test_two_distinct_fresh_messages_both_accepted(receiver, monkeypatch):
    """Sanity check that replay tracking doesn't over-trigger: two different
    genuine messages (different nonces, since encrypt() generates a fresh
    one each time) must both be accepted."""
    client, priv_a, session_key = receiver
    env1 = build_chat_envelope("alice", priv_a, session_key, "message one", int(time.time()))
    env2 = build_chat_envelope("alice", priv_a, session_key, "message two", int(time.time()))
    assert env1["nonce"] != env2["nonce"]

    out1 = _receive_and_capture(client, env1, monkeypatch)
    out2 = _receive_and_capture(client, env2, monkeypatch)
    assert "message one" in out1
    assert "message two" in out2


def test_tampering_with_timestamp_after_signing_is_caught_by_signature(receiver, monkeypatch):
    """The timestamp is covered by the signature (Phase 7b requirement): an
    attacker bumping the timestamp on a captured envelope to slip it past
    the freshness check must invalidate the signature instead."""
    client, priv_a, session_key = receiver
    old_timestamp = int(time.time()) - REPLAY_WINDOW_SECONDS - 10
    envelope = build_chat_envelope("alice", priv_a, session_key, "old but forge-updated",
                                    old_timestamp)

    # An attacker can't re-sign without alice's private key, but let's prove
    # that simply re-encrypting a "corrected" timestamp (without a valid new
    # signature) is caught by the signature check -- simulate by building a
    # fresh inner payload with a bumped timestamp but the OLD signature.
    old_signable = chat_signable_bytes("old but forge-updated", old_timestamp)
    old_signature = sign(priv_a, old_signable)
    forged_inner = json.dumps({
        "message": "old but forge-updated",
        "timestamp": int(time.time()),  # bumped to look fresh
        "signature": b64(old_signature),  # but signature still covers the OLD timestamp
    }).encode("utf-8")
    box = encrypt(session_key, forged_inner)
    forged_envelope = {
        "type": "chat", "from": "alice",
        "nonce": b64(box["nonce"]), "ciphertext": b64(box["ciphertext"]), "tag": b64(box["tag"]),
    }

    output = _receive_and_capture(client, forged_envelope, monkeypatch)
    assert "old but forge-updated" not in output
    assert "verification FAILED" in output
