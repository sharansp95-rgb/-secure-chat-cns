"""Tests for Stage C: the opt-in, lab-mode-only Attack Lab.

Covers the safety restrictions (lab_control rejected when --lab is off, or
from a non-localhost peer), the one-shot arm/fire/disarm semantics, and the
end-to-end path through real TLS clients for all four actions, each caught
by the real, unmodified client-side check it's meant to defeat.

Determinism notes: servers/clients come from the shared `net` fixture
(ephemeral ports, guaranteed teardown). End-to-end assertions wait on real
conditions (a client event / client state) with a timeout -- never on a fixed
sleep -- and rely on TCP ordering: a lab_control envelope and the chat
envelope sent right after it travel the SAME connection, so the server's
handler thread processes them in that order.
"""

import base64
import json
import time

import _demo_common as dc
from server.security_log import read_events
from server.server import ChatServer

WAIT_SECONDS = 15


def wait_until(predicate, what, timeout=WAIT_SECONDS):
    deadline = time.time() + timeout
    while not predicate():
        if time.time() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for: {what}")
        time.sleep(0.01)


def collect_events(client):
    """Record every (kind, data) event the client emits from now on."""
    events = []
    client.on_event = lambda kind, data: events.append((kind, data))
    return events


def kinds(events):
    return [k for k, _ in events]


class FakeConn:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data.decode("utf-8")))

    def last(self):
        return self.sent[-1]


def offline_server(lab_mode):
    """A ChatServer used only for its handler/route methods -- never
    listens, so there is no port at all."""
    return ChatServer("127.0.0.1", 0, lab_mode=lab_mode)


# --- safety restrictions, as unit tests on the handler directly ------------

def test_lab_control_rejected_when_lab_mode_is_off(security_log_path):
    server = offline_server(lab_mode=False)
    conn = FakeConn()
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"type": "lab_control", "action": "tamper_next"})

    assert conn.last() == {
        "type": "lab_control_result", "action": "tamper_next", "target": "alice",
        "armed": False,
        "detail": "lab mode is not enabled on this server (start it with --lab)"}
    events = read_events(security_log_path)
    assert len(events) == 1 and events[0]["event"] == "lab_control_rejected"
    assert events[0]["requested_by"] == "alice"
    assert not server._lab_pending


def test_lab_control_rejected_from_non_localhost_peer(security_log_path):
    server = offline_server(lab_mode=True)  # lab IS on
    conn = FakeConn()
    server._handle_lab_control(conn, ("203.0.113.5", 9), "alice",
                               {"type": "lab_control", "action": "tamper_next"})

    assert conn.last()["armed"] is False
    assert "localhost" in conn.last()["detail"]
    events = read_events(security_log_path)
    assert events[0]["event"] == "lab_control_rejected"
    assert events[0]["from_addr"] == "203.0.113.5"
    assert "alice" not in server._lab_pending  # nothing was armed


def test_unknown_action_is_rejected_and_nothing_armed():
    server = offline_server(lab_mode=True)
    conn = FakeConn()
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"type": "lab_control", "action": "format_the_disk"})
    assert conn.last()["armed"] is False
    assert not server._lab_pending


# --- one-shot semantics, driven directly through route() -------------------

def _fake_chat_envelope(sender, nonce=b"n" * 12, ct=b"c" * 16, tag=b"t" * 16):
    return {"type": "chat", "from": sender, "to": "bob",
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(tag).decode()}


def test_tamper_next_fires_exactly_once_then_disarms():
    server = offline_server(lab_mode=True)
    conn = FakeConn()
    server.clients["bob"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "tamper_next", "target": "alice"})
    assert server._lab_pending["alice"][0] == "tamper_next"

    env1 = _fake_chat_envelope("alice")
    server.route(dict(env1), "alice")
    assert "alice" not in server._lab_pending  # disarmed after firing once
    assert conn.last()["ciphertext"] != env1["ciphertext"]  # byte flipped

    env2 = _fake_chat_envelope("alice")
    server.route(dict(env2), "alice")
    assert conn.last()["ciphertext"] == env2["ciphertext"]  # pristine: no longer armed


def test_drop_next_fires_exactly_once_then_disarms():
    server = offline_server(lab_mode=True)
    conn = FakeConn()
    server.clients["bob"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "drop_next", "target": "alice"})

    server.route(_fake_chat_envelope("alice"), "alice")
    assert len(conn.sent) == 1  # only the lab_control_result -- the chat was dropped
    assert "alice" not in server._lab_pending

    server.route(_fake_chat_envelope("alice"), "alice")
    assert len(conn.sent) == 2  # second message relayed normally


def test_mitm_next_handshake_fires_exactly_once_then_disarms():
    server = offline_server(lab_mode=True)
    conn = FakeConn()
    server.clients["bob"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "mitm_next_handshake", "target": "alice"})

    real_pubkey = base64.b64encode(b"x" * 32).decode()
    sig = base64.b64encode(b"s" * 32).decode()
    server.route({"type": "handshake_init", "from": "alice", "to": "bob",
                  "pubkey": real_pubkey, "handshake_sig": sig}, "alice")
    assert conn.last()["pubkey"] != real_pubkey
    assert "alice" not in server._lab_pending

    server.route({"type": "handshake_init", "from": "alice", "to": "bob",
                  "pubkey": real_pubkey, "handshake_sig": sig}, "alice")
    assert conn.last()["pubkey"] == real_pubkey  # no longer armed


def test_replay_last_resends_immediately_not_on_next_message():
    server = offline_server(lab_mode=True)
    bob_conn = FakeConn()
    server.clients["bob"] = bob_conn
    original = _fake_chat_envelope("alice")
    server.route(dict(original), "alice")
    assert len(bob_conn.sent) == 1

    armer_conn = FakeConn()
    server.clients["alice"] = armer_conn
    server._handle_lab_control(armer_conn, ("127.0.0.1", 9), "alice",
                               {"action": "replay_last", "target": "alice"})
    # Fired immediately: bob now has the original PLUS the replay, with no
    # new message having been sent.
    assert len(bob_conn.sent) == 2
    assert bob_conn.sent[1]["ciphertext"] == original["ciphertext"]
    assert bob_conn.sent[1]["nonce"] == original["nonce"]  # same envelope, same nonce


def test_replay_last_with_nothing_to_replay_is_rejected():
    server = offline_server(lab_mode=True)
    conn = FakeConn()
    server.clients["alice"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "replay_last", "target": "alice"})
    assert conn.last()["armed"] is False
    assert "no previous chat message" in conn.last()["detail"]


# --- end-to-end detection, through real TLS clients -------------------------

def make_secure_pair(net):
    """Lab-mode server plus alice/bob with an established signed session.
    Returns (server, alice, bob, alice_events, bob_events)."""
    server, host, port = net.start_server(lab_mode=True)
    alice_name, bob_name = dc.demo_username("alice"), dc.demo_username("bob")
    alice = net.register_client(port, alice_name, bob_name)
    bob = net.register_client(port, bob_name, alice_name)
    assert dc.establish_signed_handshake(alice, bob, timeout=WAIT_SECONDS)
    return server, alice, bob, collect_events(alice), collect_events(bob)


def test_login_result_reports_lab_mode(net):
    _, _, port = net.start_server(lab_mode=True)
    assert net.register_attempt(port, dc.demo_username("x"))["lab_mode"] is True
    _, _, plain_port = net.start_server(lab_mode=False)
    assert net.register_attempt(plain_port, dc.demo_username("y"))["lab_mode"] is False


def test_end_to_end_tamper_is_caught_by_gcm_tag(net):
    server, alice, bob, a_events, b_events = make_secure_pair(net)
    alice.send_envelope({"type": "lab_control", "action": "tamper_next"})
    alice.send_message("do not tamper with this")

    wait_until(lambda: "message_rejected" in kinds(b_events), "bob rejecting the tampered message")
    rejected = [d for k, d in b_events if k == "message_rejected"][0]
    assert rejected["reason"] == "decryption_failed"
    assert not any(t["message"] == "do not tamper with this" for t in bob.transcript)


def test_end_to_end_drop_is_caught_as_a_chain_gap(net):
    server, alice, bob, a_events, b_events = make_secure_pair(net)
    alice.send_envelope({"type": "lab_control", "action": "drop_next"})
    alice.send_message("dropped message")
    alice.send_message("the one that exposes the gap")

    wait_until(lambda: any(t["message"] == "the one that exposes the gap"
                           for t in bob.transcript), "bob receiving the second message")
    # TCP is ordered: had the first message been delivered at all, bob would
    # have processed it before this one.
    assert not any(t["message"] == "dropped message" for t in bob.transcript)
    warnings = [d for k, d in b_events if k == "chain_warning"]
    assert len(warnings) == 1
    assert "missing" in warnings[0]["detail"]
    assert "possible deletion by the relay" in warnings[0]["detail"]


def test_end_to_end_replay_is_caught_as_a_duplicate(net):
    server, alice, bob, a_events, b_events = make_secure_pair(net)
    alice.send_message("replay me")
    alice.send_envelope({"type": "lab_control", "action": "replay_last"})

    wait_until(lambda: any(d["reason"] == "replay_duplicate"
                           for k, d in b_events if k == "message_rejected"),
               "bob rejecting the replayed duplicate")
    assert [t["message"] for t in bob.transcript].count("replay me") == 1  # shown once


def test_end_to_end_mitm_is_caught_by_handshake_signature(net):
    """The relay is armed and CONFIRMS it (lab_control_result armed=True) before bob exists.

    Bob's arrival makes alice (the lower username) start the handshake by herself, so that
    automatic handshake is the one the relay forges. Arming after both users are online is
    a race: the automatic handshake may already have started or finished, in which case
    initiate_handshake() is a no-op and no forged handshake is ever relayed."""
    server, host, port = net.start_server(lab_mode=True)
    alice_name, bob_name = dc.demo_username("alice"), dc.demo_username("bob")
    assert alice_name < bob_name          # alice is the designated initiator
    a_events = []
    alice = net.register_client(port, alice_name, bob_name,
                                event_callback=lambda k, d: a_events.append((k, d)))
    alice.send_envelope({"type": "lab_control", "action": "mitm_next_handshake"})
    wait_until(lambda: any(k == "lab_control_result" and d.get("armed") for k, d in a_events),
               "the server confirming the MITM attack is armed")

    b_events = []          # attached at creation: the abort can fire right after login
    bob = net.register_client(port, bob_name, alice_name,
                              event_callback=lambda k, d: b_events.append((k, d)))

    wait_until(lambda: "handshake_aborted" in kinds(b_events), "bob aborting the forged handshake")
    assert bob.session_key is None
    wait_until(lambda: "lab_attack_performed" in kinds(a_events), "alice told the relay performed it")


def test_lab_attack_performed_is_reported_only_to_the_armer(net):
    """The armer gets a lab_attack_performed event confirming what the relay
    did; the OTHER party never does -- they only see the (real, unprompted)
    rejection their own client already produces for a bad message."""
    server, alice, bob, a_events, b_events = make_secure_pair(net)
    alice.send_envelope({"type": "lab_control", "action": "tamper_next"})
    alice.send_message("hello")

    wait_until(lambda: "lab_attack_performed" in kinds(a_events), "alice's lab_attack_performed")
    wait_until(lambda: "message_rejected" in kinds(b_events), "bob's own rejection")
    assert "lab_attack_performed" not in kinds(b_events)
