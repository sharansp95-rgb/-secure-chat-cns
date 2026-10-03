"""Hash-chain reporting across several attacks in ONE session (tamper, replay, drop, then
normal messages): each attack is reported once and accurately, the chain resynchronises after
a gap, and the evidence export + offline verifier stay consistent. Detection stays strict:
a gap is always reported, explained or not."""

import json
import os
import sys

import pytest

import _demo_common as dc
from conftest import ROOT  # noqa: F401
from crypto_engine.hash_chain import GAP, OK, IncomingChain
from test_attack_lab import WAIT_SECONDS, kinds, make_secure_pair, wait_until

sys.path.insert(0, os.path.join(ROOT, "tools"))
import verify_transcript  # noqa: E402


def arm(alice, action):
    alice.send_envelope({"type": "lab_control", "action": action})


def shown(client, text):
    return any(t["message"] == text for t in client.transcript)


def send_and_wait(alice, bob, text):
    alice.send_message(text)
    wait_until(lambda: shown(bob, text), f"bob showing {text!r}")


def reports(events, kind):
    return [d for k, d in events if k == kind]


@pytest.fixture()
def session(net):
    server, alice, bob, a_events, b_events = make_secure_pair(net)
    return alice, bob, a_events, b_events, net


def run_attacks(alice, bob, b_events):
    """m1 ok; tamper (rejected); r ok (gap explained by the tampered one); replay r
    (duplicate); drop one message; n1 (gap: 1 really missing); n2, n3 normal."""
    send_and_wait(alice, bob, "m1 first normal message")

    arm(alice, "tamper_next")
    alice.send_message("t this one is tampered in transit")
    wait_until(lambda: len(reports(b_events, "message_rejected")) == 1, "the tamper rejection")

    send_and_wait(alice, bob, "r a normal message after the tamper")
    arm(alice, "replay_last")
    wait_until(lambda: len(reports(b_events, "message_rejected")) == 2, "the replay rejection")

    arm(alice, "drop_next")
    alice.send_message("d this message is dropped by the relay")
    send_and_wait(alice, bob, "n1 first message after the drop")
    send_and_wait(alice, bob, "n2 second normal message")
    send_and_wait(alice, bob, "n3 third normal message")


def test_each_attack_is_reported_once_and_accurately(session):
    alice, bob, a_events, b_events, net = session
    run_attacks(alice, bob, b_events)

    rejected = reports(b_events, "message_rejected")
    assert [d["reason"] for d in rejected] == ["decryption_failed", "replay_duplicate"]

    gaps = reports(b_events, "chain_warning")
    assert len(gaps) == 2, f"exactly one warning per gap, got {[g['detail'] for g in gaps]}"
    after_tamper, after_drop = gaps
    # 1) the tampered message was sent (its seq was used) but rejected: 1 missing, explained
    assert (after_tamper["missing"], after_tamper["explained"]) == (1, 1)
    assert "matches 1 message(s) rejected earlier" in after_tamper["detail"]
    # 2) the dropped message: 1 missing, nothing blocked for it -> possible deletion
    assert (after_drop["missing"], after_drop["explained"]) == (1, 0)
    assert "possible deletion by the relay" in after_drop["detail"]
    assert after_drop["detail"].startswith("1 message(s) missing before #")


def test_messages_after_a_gap_are_verified_again(session):
    alice, bob, a_events, b_events, net = session
    run_attacks(alice, bob, b_events)
    received = reports(b_events, "message_received")
    by_text = {d["message"]: d["receipt"]["chain_link"] for d in received}
    assert by_text["m1 first normal message"] == "ok"
    assert by_text["r a normal message after the tamper"] == "gap"       # flagged: it follows the tamper
    assert by_text["n1 first message after the drop"] == "gap"           # flagged: it follows the drop
    assert by_text["n2 second normal message"] == "ok"                   # resynchronised
    assert by_text["n3 third normal message"] == "ok"
    assert not shown(bob, "t this one is tampered in transit")
    assert not shown(bob, "d this message is dropped by the relay")
    assert [t["message"] for t in bob.transcript].count("r a normal message after the tamper") == 1


def test_evidence_records_the_gaps_and_the_verifier_explains_them(session, tmp_path):
    alice, bob, a_events, b_events, net = session
    run_attacks(alice, bob, b_events)
    path = bob.export_evidence(str(tmp_path))
    data = json.load(open(path))
    kinds_recorded = [(e["kind"], e["reason"]) for e in data["rejected_events"]]
    assert kinds_recorded.count(("chain_warning", "chain_gap")) == 2
    assert ("message_rejected", "decryption_failed") in kinds_recorded
    assert any("matches 1 message(s) rejected earlier" in (e["detail"] or "") for e in data["rejected_events"])

    report = verify_transcript.verify_evidence(data)
    chain_failures = [f for f in report.failures if f[1] == "chain"]
    assert len(chain_failures) == 2, "one verifier finding per real gap (it resynchronises too)"
    assert not [f for f in report.failures if f[1] != "chain"], "signatures and hashes all verify"
    assert not report.valid, "a gap keeps the file INVALID: the missing messages are not in it"
    assert all("GAP: 1 message(s) from" in f[2] for f in chain_failures)
    assert all("records 1 rejected message(s)" in f[2] for f in chain_failures), \
        "the verifier tells the reader the export itself recorded the rejected message"
    # the records after the second gap verify cleanly
    assert any("n3 third normal message" in line and "chain ✔" in line for line in report.lines)


# ---- pure chain logic ---------------------------------------------------------------------

def make_chain():
    return IncomingChain("alice", "0" * 64)


def feed(chain, seq, prev, text="x"):
    return chain.check("bob", seq, 1.0, text, prev)


def test_a_dropped_message_is_one_missing_not_three():
    from crypto_engine.hash_chain import canonical_record, record_hash
    chain = make_chain()
    v = feed(chain, 4, "whatever")        # #1..#3 never arrived and nothing was rejected
    assert v.status == GAP and (v.missing, v.explained) == (3, 0)
    # the very next message links to the received one: back to normal
    prev = record_hash(canonical_record("alice", "bob", 4, 1.0, "x", "whatever"))
    assert feed(chain, 5, prev).status == OK


def test_rejected_messages_explain_gaps_but_never_hide_them():
    chain = make_chain()
    chain.note_rejected("n1")
    chain.note_rejected("n1")             # the same bad message delivered twice counts once
    v = feed(chain, 3, "p")               # #1 and #2 missing, one rejected message to account for
    assert v.status == GAP, "an explained gap is still reported"
    assert (v.missing, v.explained) == (2, 1)
    assert "1 match message(s) rejected earlier, 1 unaccounted for" in v.detail
    assert chain._rejected_nonces == set(), "resynchronised: nothing carries over"


def test_a_rejection_does_not_leak_into_a_later_unrelated_gap():
    from crypto_engine.hash_chain import canonical_record, record_hash
    chain = make_chain()
    chain.note_rejected("bad")
    prev = chain.head
    assert feed(chain, 1, prev).status == OK       # the next message is in order
    prev2 = record_hash(canonical_record("alice", "bob", 1, 1.0, "x", prev))
    v = feed(chain, 3, prev2)                      # now one is really missing
    assert (v.missing, v.explained) == (1, 0), "the old rejection must not explain this gap"
