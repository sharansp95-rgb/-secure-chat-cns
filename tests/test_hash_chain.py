"""Tests for Stage A: the hash-chained conversation log.

Per-message AES-GCM + RSA signatures prove each message is authentic, but a
malicious relay could still silently drop or reorder valid messages. These
tests cover the chain primitives (crypto_engine/hash_chain.py) and the real
send -> sign -> encrypt -> decrypt -> verify -> chain-check pipeline in
SecureChatClient.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import SecureChatClient  # noqa: E402
from crypto_engine.hash_chain import (  # noqa: E402
    BROKEN,
    GAP,
    OK,
    IncomingChain,
    OutgoingChain,
    canonical_record,
    genesis_hash,
    record_hash,
)
from crypto_engine.signatures import generate_keypair, serialize_public_key  # noqa: E402

PUB_I = b"\x01" * 32
PUB_R = b"\x02" * 32
GENESIS = genesis_hash(PUB_I, PUB_R, "alice")


def make_records(count, sender="alice", recipient="bob", genesis=GENESIS):
    """`count` consecutive records from one sender, as (fields dict) in order."""
    out = OutgoingChain(sender, genesis)
    records = []
    for i in range(count):
        seq, prev = out.next_fields()
        fields = {"recipient": recipient, "seq": seq, "timestamp": 1000 + i,
                  "message": f"message {seq}", "prev_hash": prev}
        out.commit(canonical_record(sender, recipient, seq, fields["timestamp"],
                                    fields["message"], prev))
        records.append(fields)
    return records


def feed(chain, fields):
    return chain.check(fields["recipient"], fields["seq"], fields["timestamp"],
                       fields["message"], fields["prev_hash"])


# --- chain primitives --------------------------------------------------------

def test_in_order_sequence_verifies():
    chain = IncomingChain("alice", GENESIS)
    verdicts = [feed(chain, r) for r in make_records(5)]
    assert [v.status for v in verdicts] == [OK] * 5


def test_dropped_message_is_detected_as_a_gap():
    records = make_records(4)
    chain = IncomingChain("alice", GENESIS)
    assert feed(chain, records[0]).status == OK
    # records[1] (seq 2) silently dropped by the relay
    verdict = feed(chain, records[2])
    assert verdict.status == GAP
    assert verdict.expected_seq == 2 and verdict.got_seq == 3
    assert "missing" in verdict.detail
    # The chain resyncs to the authentic message: seq 4 is fine afterwards.
    assert feed(chain, records[3]).status == OK


def test_swapped_order_is_detected():
    records = make_records(3)
    chain = IncomingChain("alice", GENESIS)
    assert feed(chain, records[0]).status == OK
    # relay delivers seq 3 before seq 2
    assert feed(chain, records[2]).status == GAP
    late = feed(chain, records[1])
    assert late.status == BROKEN
    assert "backwards" in late.detail


def test_sequence_going_backwards_is_detected():
    records = make_records(2)
    chain = IncomingChain("alice", GENESIS)
    feed(chain, records[0])
    feed(chain, records[1])
    assert feed(chain, records[0]).status == BROKEN  # seq 1 again


def test_injected_message_with_wrong_prev_hash_is_detected():
    records = make_records(2)
    chain = IncomingChain("alice", GENESIS)
    assert feed(chain, records[0]).status == OK
    forged = dict(records[1], message="injected", prev_hash="ab" * 32)
    verdict = feed(chain, forged)
    assert verdict.status == BROKEN
    assert "prev_hash" in verdict.detail
    # A broken record must not advance the chain: the genuine one still fits.
    assert feed(chain, records[1]).status == OK


def test_first_message_must_link_to_genesis():
    chain = IncomingChain("alice", GENESIS)
    bad_first = dict(make_records(1)[0], prev_hash="00" * 32)
    assert feed(chain, bad_first).status == BROKEN


def test_genesis_is_session_specific_and_direction_specific():
    other_session = genesis_hash(b"\x09" * 32, PUB_R, "alice")
    assert other_session != GENESIS
    assert genesis_hash(PUB_I, PUB_R, "bob") != GENESIS
    assert genesis_hash(PUB_I, PUB_R, "alice") == GENESIS  # deterministic


def test_canonical_record_is_stable_and_key_order_independent():
    a = canonical_record("alice", "bob", 1, 5, "hi", "00" * 32)
    b = canonical_record("alice", "bob", 1, 5, "hi", "00" * 32)
    assert a == b
    decoded = json.loads(a)
    assert list(decoded) == sorted(decoded)  # sorted keys, no spaces
    assert b" " not in a.replace(b"hi", b"")


# --- integration through the real client pipeline ---------------------------

class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data.decode("utf-8")))


@pytest.fixture()
def pair():
    """Two real SecureChatClients that complete a real RSA-signed ECDH
    handshake with each other through their real handlers (no sockets)."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    events_b = []
    a = SecureChatClient(FakeSocket(), "alice", "bob")
    b = SecureChatClient(FakeSocket(), "bob", "alice",
                         event_callback=lambda k, d: events_b.append((k, d)))
    a.rsa_private_key, b.rsa_private_key = priv_a, priv_b
    a.peer_public_key, b.peer_public_key = pub_b, pub_a
    a.peer_public_key_pem = serialize_public_key(pub_b).decode("ascii")
    b.peer_public_key_pem = serialize_public_key(pub_a).decode("ascii")

    a.initiate_handshake()
    b._handle_handshake_init(a.sock.sent[-1])
    a._handle_handshake_response(b.sock.sent[-1])
    assert a.session_key is not None and a.session_key == b.session_key
    return a, b, events_b


def send_and_collect(sender, text):
    sender.send_message(text)
    return sender.sock.sent[-1]


def kinds(events):
    return [k for k, _ in events]


def test_both_sides_derive_the_same_genesis(pair):
    a, b, _ = pair
    assert a._out_chain.head == b._in_chain.head
    assert b._out_chain.head == a._in_chain.head
    assert a._out_chain.head != b._out_chain.head  # per-direction


def test_real_pipeline_in_order_has_no_warnings(pair, capsys):
    a, b, events = pair
    for text in ("one", "two", "three"):
        b._handle_chat(send_and_collect(a, text))
    assert kinds(events).count("message_received") == 3
    assert "chain_warning" not in kinds(events)
    assert "message_rejected" not in kinds(events)
    assert [t["seq"] for t in b.transcript] == [1, 2, 3]
    assert b._in_chain.head == a._out_chain.head


def test_real_pipeline_detects_relay_dropping_a_message(pair, capsys):
    a, b, events = pair
    first = send_and_collect(a, "one")
    send_and_collect(a, "two")            # the relay silently drops this one
    third = send_and_collect(a, "three")
    b._handle_chat(first)
    b._handle_chat(third)
    warnings = [d for k, d in events if k == "chain_warning"]
    assert len(warnings) == 1
    assert "missing" in warnings[0]["detail"]
    assert "possible deletion by the relay" in capsys.readouterr().out
    # The authentic third message is still delivered, flagged by the warning.
    assert [d["message"] for k, d in events if k == "message_received"] == ["one", "three"]
    assert b.rejected_events and b.rejected_events[0]["reason"] == "chain_gap"


def test_real_pipeline_detects_reordering(pair, capsys):
    a, b, events = pair
    envs = [send_and_collect(a, t) for t in ("one", "two", "three")]
    b._handle_chat(envs[0])
    b._handle_chat(envs[2])   # three arrives before two
    b._handle_chat(envs[1])
    assert "chain_warning" in kinds(events)
    rejected = [d for k, d in events if k == "message_rejected"]
    assert rejected and rejected[0]["reason"] == "chain_broken"
    assert "two" not in [d["message"] for k, d in events if k == "message_received"]


def test_chain_fields_are_covered_by_the_signature(pair):
    """Altering seq inside an otherwise valid payload must fail the RSA
    signature check (the relay can't edit it anyway -- it's encrypted -- but
    even a holder of the session key cannot re-label a message)."""
    from client.client import b64, unb64
    from crypto_engine.aes_gcm import decrypt, encrypt

    a, b, events = pair
    env = send_and_collect(a, "one")
    inner = json.loads(decrypt(a.session_key, unb64(env["nonce"]),
                               unb64(env["ciphertext"]), unb64(env["tag"])))
    inner["seq"] = 7  # re-label as message 7
    box = encrypt(a.session_key, json.dumps(inner).encode("utf-8"))
    forged = dict(env, nonce=b64(box["nonce"]), ciphertext=b64(box["ciphertext"]),
                  tag=b64(box["tag"]))
    b._handle_chat(forged)
    rejected = [d for k, d in events if k == "message_rejected"]
    assert rejected and rejected[0]["reason"] == "signature_failed"


def test_sent_and_received_records_hash_identically(pair):
    a, b, events = pair
    b._handle_chat(send_and_collect(a, "one"))
    sent = a.transcript[0]
    got = b.transcript[0]
    assert sent["record_hash"] == got["record_hash"]
    assert sent["signature"] == got["signature"]
    recomputed = record_hash(canonical_record("alice", "bob", sent["seq"], sent["timestamp"],
                                              sent["message"], sent["prev_hash"]))
    assert recomputed == sent["record_hash"]
