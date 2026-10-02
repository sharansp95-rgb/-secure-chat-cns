"""Tests for Stage C: the opt-in, lab-mode-only Attack Lab.

Covers the safety restrictions (lab_control rejected when --lab is off, or
from a non-localhost peer), the one-shot arm/fire/disarm semantics, and the
end-to-end path through real TLS clients for all four actions, each caught
by the real, unmodified client-side check it's meant to defeat.
"""

import base64
import json
import os
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))

import _demo_common as dc  # noqa: E402
from server.security_log import DEFAULT_LOG_PATH, read_events  # noqa: E402
from server.server import CertsMissingError, ChatServer  # noqa: E402


def start_lab_relay(host="127.0.0.1"):
    """Like demo._demo_common.start_mini_relay, but with lab_mode=True --
    kept here rather than editing that shared helper (which every
    demo/run_*.py script also uses and which must keep working unmodified)."""
    port = dc.free_port()
    try:
        server = ChatServer(host, port, lab_mode=True)
    except CertsMissingError as exc:
        pytest.skip(f"certs not generated: {exc}")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    assert dc.wait_for_port(host, port, timeout=5)
    return server, host, port


class FakeConn:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data.decode("utf-8")))

    def last(self):
        return self.sent[-1]


# --- safety restrictions, as unit tests on the handler directly ------------

def test_lab_control_rejected_when_lab_mode_is_off(tmp_path):
    log_path = tmp_path / "events.jsonl"
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=False)
    conn = FakeConn()
    import server.server as server_module
    orig = server_module.log_event
    server_module.log_event = lambda *a, **k: orig(*a, path=str(log_path), **k)
    try:
        server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                                   {"type": "lab_control", "action": "tamper_next"})
    finally:
        server_module.log_event = orig

    result = conn.last()
    assert result == {"type": "lab_control_result", "action": "tamper_next",
                      "target": "alice", "armed": False,
                      "detail": "lab mode is not enabled on this server (start it with --lab)"}
    events = read_events(str(log_path))
    assert len(events) == 1 and events[0]["event"] == "lab_control_rejected"
    assert events[0]["requested_by"] == "alice"


def test_lab_control_rejected_from_non_localhost_peer(tmp_path):
    log_path = tmp_path / "events.jsonl"
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)  # lab IS on
    conn = FakeConn()
    import server.server as server_module
    orig = server_module.log_event
    server_module.log_event = lambda *a, **k: orig(*a, path=str(log_path), **k)
    try:
        server._handle_lab_control(conn, ("203.0.113.5", 9), "alice",
                                   {"type": "lab_control", "action": "tamper_next"})
    finally:
        server_module.log_event = orig

    result = conn.last()
    assert result["armed"] is False
    assert "localhost" in result["detail"]
    events = read_events(str(log_path))
    assert events[0]["event"] == "lab_control_rejected"
    assert events[0]["from_addr"] == "203.0.113.5"
    # Nothing was actually armed.
    assert "alice" not in server._lab_pending


def test_unknown_action_is_rejected_and_nothing_armed():
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
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
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
    conn = FakeConn()
    server.clients["bob"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "tamper_next", "target": "alice"})
    assert server._lab_pending["alice"][0] == "tamper_next"

    env1 = _fake_chat_envelope("alice")
    server.route(dict(env1), "alice")
    assert "alice" not in server._lab_pending  # disarmed after firing once
    delivered1 = conn.last()
    assert delivered1["ciphertext"] != env1["ciphertext"]  # byte flipped

    env2 = _fake_chat_envelope("alice")
    server.route(dict(env2), "alice")
    delivered2 = conn.last()
    assert delivered2["ciphertext"] == env2["ciphertext"]  # pristine: no longer armed


def test_drop_next_fires_exactly_once_then_disarms():
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
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
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
    conn = FakeConn()
    server.clients["bob"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "mitm_next_handshake", "target": "alice"})

    real_pubkey = base64.b64encode(b"x" * 32).decode()
    env1 = {"type": "handshake_init", "from": "alice", "to": "bob",
            "pubkey": real_pubkey, "handshake_sig": base64.b64encode(b"s" * 32).decode()}
    server.route(dict(env1), "alice")
    forged = conn.last()
    assert forged["pubkey"] != real_pubkey
    assert "alice" not in server._lab_pending

    env2 = {"type": "handshake_init", "from": "alice", "to": "bob",
            "pubkey": real_pubkey, "handshake_sig": base64.b64encode(b"s" * 32).decode()}
    server.route(dict(env2), "alice")
    assert conn.last()["pubkey"] == real_pubkey  # no longer armed


def test_replay_last_resends_immediately_not_on_next_message():
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
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
    server = ChatServer("127.0.0.1", dc.free_port(), lab_mode=True)
    conn = FakeConn()
    server.clients["alice"] = conn
    server._handle_lab_control(conn, ("127.0.0.1", 9), "alice",
                               {"action": "replay_last", "target": "alice"})
    assert conn.last()["armed"] is False
    assert "no previous chat message" in conn.last()["detail"]


# --- end-to-end detection, through real TLS clients -------------------------

@pytest.fixture()
def lab_pair():
    server, host, port = start_lab_relay()
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    alice = dc.register_client(host, port, alice_name, bob_name)
    bob = dc.register_client(host, port, bob_name, alice_name)
    assert dc.establish_signed_handshake(alice, bob)
    return server, alice, bob


def test_login_result_reports_lab_mode(lab_pair):
    import client.client as client_module

    server, host, port = start_lab_relay()
    sock = client_module.connect_tls(host, port)
    from client.client import SecureChatClient
    c = SecureChatClient(sock, username=None, peer="x")
    threading.Thread(target=c.receive_loop, daemon=True).start()
    c.register("libtest_" + dc.demo_username("x"), "Demo-Password-1234!",
               public_key_pem=None)
    result = c.auth_results.get(timeout=5)
    assert result["success"] and result["lab_mode"] is True
    c.stop_event.set()
    sock.close()


def test_end_to_end_tamper_is_caught_by_gcm_tag(lab_pair, capsys):
    server, alice, bob = lab_pair
    alice.send_envelope({"type": "lab_control", "action": "tamper_next"})
    time.sleep(0.3)
    alice.send_message("do not tamper with this")
    time.sleep(0.5)
    out = capsys.readouterr().out
    assert "do not tamper with this" not in out
    assert "failed authentication" in out or "WARNING" in out


def test_end_to_end_drop_is_caught_as_a_chain_gap(lab_pair, capsys):
    server, alice, bob = lab_pair
    alice.send_envelope({"type": "lab_control", "action": "drop_next"})
    time.sleep(0.3)
    alice.send_message("dropped message")
    time.sleep(0.3)
    alice.send_message("the one that exposes the gap")
    time.sleep(0.5)
    out = capsys.readouterr().out
    assert "dropped message" not in out
    assert "missing" in out and "possible deletion by the relay" in out
    assert "the one that exposes the gap" in out


def test_end_to_end_replay_is_caught_as_a_duplicate(lab_pair, capsys):
    server, alice, bob = lab_pair
    alice.send_message("replay me")
    time.sleep(0.3)
    alice.send_envelope({"type": "lab_control", "action": "replay_last"})
    time.sleep(0.5)
    out = capsys.readouterr().out
    assert out.count("replay me") == 1  # shown once, not twice
    assert "duplicate message detected" in out


def test_end_to_end_mitm_is_caught_by_handshake_signature(capsys):
    server, host, port = start_lab_relay()
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    alice = dc.register_client(host, port, alice_name, bob_name)
    bob = dc.register_client(host, port, bob_name, alice_name)
    assert bob.fetch_peer_public_key(timeout=5)
    assert alice.fetch_peer_public_key(timeout=5)

    alice.send_envelope({"type": "lab_control", "action": "mitm_next_handshake"})
    time.sleep(0.3)
    alice.initiate_handshake()
    time.sleep(0.5)

    assert bob.session_key is None
    out = capsys.readouterr().out
    assert "HANDSHAKE ABORTED" in out


def test_lab_attack_performed_is_reported_only_to_the_armer():
    """The armer gets a lab_attack_performed event confirming what the relay
    did; the OTHER party never does -- they only see the (real, unprompted)
    rejection their own client already produces for a bad message."""
    server, host, port = start_lab_relay()
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    alice_events, bob_events = [], []

    def make_client(username, peer, events):
        sock = dc.connect_tls(host, port)
        c = dc.SecureChatClient(sock, username=username, peer=peer,
                                event_callback=lambda k, d: events.append(k))
        threading.Thread(target=c.receive_loop, daemon=True).start()
        from crypto_engine.signatures import generate_keypair as gen_rsa, serialize_public_key
        priv, pub = gen_rsa()
        c.register(username, dc.DEMO_PASSWORD, public_key_pem=serialize_public_key(pub).decode())
        result = c.auth_results.get(timeout=10)
        assert result and result["success"]
        c.rsa_private_key = priv
        from auth.keystore import save_private_key
        save_private_key(username, priv)
        return c

    alice = make_client(alice_name, bob_name, alice_events)
    bob = make_client(bob_name, alice_name, bob_events)
    assert dc.establish_signed_handshake(alice, bob)
    alice_events.clear()
    bob_events.clear()

    alice.send_envelope({"type": "lab_control", "action": "tamper_next"})
    time.sleep(0.3)
    alice.send_message("hello")
    time.sleep(0.5)

    assert "lab_attack_performed" in alice_events
    assert "lab_attack_performed" not in bob_events
    assert "message_rejected" in bob_events  # bob's own, unprompted detection
