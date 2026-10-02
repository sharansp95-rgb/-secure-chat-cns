"""Tests for Stage B: signed evidence export + the standalone offline verifier.

A real two-client conversation is exported, then the verifier
(tools/verify_transcript.py) is run on the untouched file (must be VALID) and
on deliberately tampered copies (must be INVALID, naming what failed).
"""

import ast
import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import verify_transcript  # noqa: E402
from client.client import SecureChatClient, b64  # noqa: E402
from client.evidence import EvidenceError, build_evidence  # noqa: E402
from crypto_engine.hash_chain import canonical_json  # noqa: E402
from crypto_engine.signatures import (  # noqa: E402
    generate_keypair,
    serialize_public_key,
    sign,
)


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data.decode("utf-8")))


@pytest.fixture()
def convo():
    """alice <-> bob after a real handshake and a short real conversation
    (alice x3, bob x2). Returns the two clients and bob's exported evidence."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    a = SecureChatClient(FakeSocket(), "alice", "bob")
    b = SecureChatClient(FakeSocket(), "bob", "alice")
    a.rsa_private_key, b.rsa_private_key = priv_a, priv_b
    a.peer_public_key, b.peer_public_key = pub_b, pub_a
    a.peer_public_key_pem = serialize_public_key(pub_b).decode("ascii")
    b.peer_public_key_pem = serialize_public_key(pub_a).decode("ascii")
    a.initiate_handshake()
    b._handle_handshake_init(a.sock.sent[-1])
    a._handle_handshake_response(b.sock.sent[-1])

    def say(sender, receiver, text):
        sender.send_message(text)
        receiver._handle_chat(sender.sock.sent[-1])

    say(a, b, "Approve transfer of $500 to Acme")
    say(b, a, "Approved, ref 7731")
    say(a, b, "Thanks, executing now")
    say(b, a, "Confirmed")
    say(a, b, "Closing the ticket")
    return a, b, build_evidence(b)


def resign(evidence, private_key):
    """Re-sign an edited file as its exporter would (used to show that the
    HASH CHAIN catches edits even if the export signature is forged)."""
    body = {k: v for k, v in evidence.items() if k != "exporter_signature"}
    evidence["exporter_signature"] = b64(sign(private_key, canonical_json(body)))
    return evidence


def failed_checks(report):
    return {(idx, check) for idx, check, _ in report.failures}


def message_index(evidence, text):
    return next(i for i, r in enumerate(evidence["records"], start=1)
                if r["message"] == text)


# --- clean export ------------------------------------------------------------

def test_clean_export_verifies_valid(convo):
    _, _, evidence = convo
    report = verify_transcript.verify_evidence(evidence)
    assert report.valid, report.render()
    assert "RESULT: VALID" in report.render()
    assert len(evidence["records"]) == 5


def test_export_contains_both_directions_keys_and_chain_heads(convo):
    a, b, evidence = convo
    assert {r["sender"] for r in evidence["records"]} == {"alice", "bob"}
    assert set(evidence["participants"]) == {"alice", "bob"}
    for info in evidence["participants"].values():
        assert info["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
        assert len(info["fingerprint"].split()) == 4
    assert evidence["chain_heads"]["alice"] == a._out_chain.head
    assert evidence["chain_heads"]["bob"] == b._out_chain.head
    assert evidence["exported_by"] == "bob"


def test_export_written_to_disk_is_verifiable_via_the_cli(convo, tmp_path, capsys):
    _, b, _ = convo
    path = b.export_evidence(str(tmp_path))
    assert os.path.dirname(path) == str(tmp_path)
    assert verify_transcript.main([path]) == 0
    assert "RESULT: VALID" in capsys.readouterr().out


def test_cannot_export_before_a_session_exists():
    client = SecureChatClient(FakeSocket(), "alice", "bob")
    with pytest.raises(EvidenceError):
        build_evidence(client)


def test_rejected_messages_are_listed_separately_never_in_records(convo):
    a, b, _ = convo
    a.send_message("one the relay will drop")   # never delivered to bob
    a.send_message("delivered after the gap")
    b._handle_chat(a.sock.sent[-1])
    evidence = build_evidence(b)
    assert [e["reason"] for e in evidence["rejected_events"]] == ["chain_gap"]
    # The authentic message that arrived IS a record; the dropped one is not.
    texts = [r["message"] for r in evidence["records"]]
    assert "delivered after the gap" in texts and "one the relay will drop" not in texts
    # ... and the verifier reports the missing message rather than hiding it.
    report = verify_transcript.verify_evidence(evidence)
    assert not report.valid
    assert any(check == "chain" and "missing" in text for _, check, text in report.failures)


# --- tampering ---------------------------------------------------------------

def test_editing_one_message_makes_it_invalid_and_names_that_message(convo):
    _, _, evidence = convo
    tampered = copy.deepcopy(evidence)
    idx = message_index(tampered, "Approve transfer of $500 to Acme")
    tampered["records"][idx - 1]["message"] = "Approve transfer of $5000 to Acme"
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert (idx, "signature") in failed_checks(report)
    first_index = report.failures[0][0]
    assert first_index == idx
    assert f"record #{idx}" in report.render()


def test_editing_a_message_is_caught_even_if_exporter_resigns(convo):
    a, b, evidence = convo
    tampered = copy.deepcopy(evidence)
    tampered["records"][0]["message"] = "Approve transfer of $9 to Acme"
    resign(tampered, b.rsa_private_key)            # exporter signature now fine
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert (1, "signature") in failed_checks(report)
    assert not any(check == "export signature" for _, check, _ in report.failures)


def test_deleting_a_record_is_caught_by_the_chain(convo):
    _, b, evidence = convo
    tampered = copy.deepcopy(evidence)
    del tampered["records"][2]                     # alice's 2nd message
    resign(tampered, b.rsa_private_key)            # even with a valid export signature
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert any(check == "chain" and "missing" in text
               for _, check, text in report.failures), report.render()


def test_deleting_the_last_record_is_caught_by_the_chain_head(convo):
    _, b, evidence = convo
    tampered = copy.deepcopy(evidence)
    tampered["records"].pop()                      # alice's last message
    resign(tampered, b.rsa_private_key)
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert any(check == "chain head" for _, check, _ in report.failures)


def test_reordering_records_is_caught(convo):
    _, b, evidence = convo
    tampered = copy.deepcopy(evidence)
    recs = tampered["records"]
    recs[0], recs[2] = recs[2], recs[0]            # swap two of alice's messages
    resign(tampered, b.rsa_private_key)
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert any(check == "chain" for _, check, _ in report.failures), report.render()


def test_editing_metadata_breaks_the_exporter_signature(convo):
    _, _, evidence = convo
    tampered = copy.deepcopy(evidence)
    tampered["session"]["started_at"] += 3600
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    assert ("export signature" in {c for _, c, _ in report.failures})
    # ... but every individual message is still genuinely signed.
    assert not any(check == "signature" for _, check, _ in report.failures)


def test_swapping_in_a_different_public_key_fails_the_signatures(convo):
    _, _, evidence = convo
    attacker_priv, attacker_pub = generate_keypair()
    tampered = copy.deepcopy(evidence)
    tampered["participants"]["alice"]["public_key_pem"] = \
        serialize_public_key(attacker_pub).decode("ascii")
    report = verify_transcript.verify_evidence(tampered)
    assert not report.valid
    checks = {c for _, c, _ in report.failures}
    assert "signature" in checks and "fingerprint" in checks
    # alice's records (1, 3, 5) no longer verify under the swapped key.
    assert {1, 3, 5} <= {i for i, c, _ in report.failures if c == "signature"}


def test_fully_forged_file_is_only_caught_by_a_pinned_fingerprint(convo):
    """Honest limitation, made explicit: someone can fabricate an entire
    self-consistent evidence file with their OWN keys. It verifies against
    itself -- which is why --expect-fingerprint exists."""
    a, b, evidence = convo
    real_alice_fp = evidence["participants"]["alice"]["fingerprint"]
    forger = SecureChatClient(FakeSocket(), "alice", "bob")
    forger.rsa_private_key, _ = generate_keypair()
    # A forger-made conversation under the same names but their own keys:
    other_priv_b, other_pub_b = generate_keypair()
    forger.peer_public_key, forger.peer_public_key_pem = other_pub_b, \
        serialize_public_key(other_pub_b).decode("ascii")
    bob2 = SecureChatClient(FakeSocket(), "bob", "alice")
    bob2.rsa_private_key = other_priv_b
    bob2.peer_public_key = forger.rsa_private_key.public_key()
    bob2.peer_public_key_pem = serialize_public_key(bob2.peer_public_key).decode("ascii")
    forger.initiate_handshake()
    bob2._handle_handshake_init(forger.sock.sent[-1])
    forger._handle_handshake_response(bob2.sock.sent[-1])
    forger.send_message("I never approved this")
    bob2._handle_chat(forger.sock.sent[-1])
    fake = build_evidence(bob2)

    assert verify_transcript.verify_evidence(fake).valid                       # self-consistent
    assert not verify_transcript.verify_evidence(
        fake, expect_fingerprints=[real_alice_fp]).valid                       # pin catches it


# --- fingerprint pinning -----------------------------------------------------

def test_expect_fingerprint_accepts_a_real_participant(convo):
    _, _, evidence = convo
    fp = evidence["participants"]["alice"]["fingerprint"]
    assert verify_transcript.verify_evidence(evidence, [fp]).valid
    assert verify_transcript.verify_evidence(evidence, [fp.lower()]).valid


def test_expect_fingerprint_rejects_an_unknown_one(convo):
    _, _, evidence = convo
    report = verify_transcript.verify_evidence(evidence, ["0000 0000 0000 0000"])
    assert not report.valid
    assert any(check == "pinned fingerprint" for _, check, _ in report.failures)


def test_cli_exit_codes(convo, tmp_path):
    _, b, evidence = convo
    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    good.write_text(json.dumps(evidence))
    tampered = copy.deepcopy(evidence)
    tampered["records"][0]["message"] = "edited"
    bad.write_text(json.dumps(tampered))
    assert verify_transcript.main([str(good)]) == 0
    assert verify_transcript.main([str(bad)]) == 1
    assert verify_transcript.main([str(tmp_path / "missing.json")]) == 2


# --- independence ------------------------------------------------------------

def test_verifier_imports_no_client_or_server_code():
    source = open(os.path.join(ROOT, "tools", "verify_transcript.py")).read()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"client", "server", "gui", "auth"}, imported
    allowed = {"argparse", "base64", "json", "os", "sys", "crypto_engine"}
    assert imported <= allowed, imported - allowed
