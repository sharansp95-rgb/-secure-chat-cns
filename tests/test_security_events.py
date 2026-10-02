"""Tests for Stage D's security event log, its server.py call sites, and the
client-side security_alert envelope.

Covers: events are valid JSON lines with the expected fields and carry no
plaintext/password/key material; security_alert envelopes are logged
correctly; and the full login-lockout flow end to end through real TLS
clients, including that a locked attempt never reaches PBKDF2.

Every test uses the shared `net` fixture (tests/conftest.py): ephemeral-port
servers that are already listening when they are returned, per-test fresh
lockout/rate-limit state, a per-test event log, and guaranteed teardown.
"""

import json
import os
import socket
import time
from unittest.mock import patch


from conftest import wait_for_events
import _demo_common as dc
from client.client import b64
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair
from crypto_engine.signatures import generate_keypair, serialize_public_key, sign
from server.lockout import LockoutGuard
from server.security_log import log_event, read_events

SENSITIVE_SUBSTRINGS = ("password", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                        "session_key", "plaintext")


# --- event log mechanics ------------------------------------------------------

def test_log_event_writes_a_valid_json_line(tmp_path):
    path = tmp_path / "events.jsonl"
    log_event("user_login", path=str(path), username="alice", from_addr="127.0.0.1")
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "user_login"
    assert record["username"] == "alice"
    assert isinstance(record["ts"], float)


def test_multiple_events_are_separate_lines_and_all_parse(tmp_path):
    path = tmp_path / "events.jsonl"
    for i in range(5):
        log_event("failed_login", path=str(path), username=f"user{i}")
    events = read_events(str(path))
    assert len(events) == 5
    assert [e["username"] for e in events] == [f"user{i}" for i in range(5)]


def test_read_events_on_missing_file_returns_empty_list(tmp_path):
    assert read_events(str(tmp_path / "nope.jsonl")) == []


# --- end-to-end: register/login produce the right events, no secrets --------

def test_register_and_login_produce_expected_events_with_no_secrets(net, security_log_path):
    server, host, port = net.start_server()
    username = dc.demo_username("evt")
    client = net.register_client(port, username, "nobody")
    net.disconnect(server, client)

    registered = wait_for_events(security_log_path, "user_registered")
    assert registered[0]["username"] == username
    assert registered[0]["from_addr"] == "127.0.0.1"

    raw = open(security_log_path).read()
    for secret in SENSITIVE_SUBSTRINGS:
        assert secret not in raw
    assert dc.DEMO_PASSWORD not in raw


def test_failed_login_is_logged_with_no_password(net, security_log_path):
    server, host, port = net.start_server()
    username = dc.demo_username("evt")
    net.disconnect(server, net.register_client(port, username, "nobody"))

    result = net.login_attempt(port, username, "definitely-the-wrong-password")
    assert result["success"] is False

    failures = wait_for_events(security_log_path, "failed_login")
    assert failures[0]["username"] == username
    assert "definitely-the-wrong-password" not in open(security_log_path).read()


def test_malformed_envelope_is_logged(net, security_log_path):
    server, host, port = net.start_server()
    username = dc.demo_username("evt")
    client = net.register_client(port, username, "nobody")
    client.sock.sendall(b"{not valid json at all\n")
    events = wait_for_events(security_log_path, "malformed_envelope")
    assert events[0]["from_user"] == username


def test_non_tls_connection_is_logged(net, security_log_path):
    server, host, port = net.start_server()
    raw = socket.create_connection((host, port), timeout=5)
    try:
        raw.sendall(b"not tls at all\n")
        try:
            raw.recv(16)
        except OSError:
            pass
    finally:
        raw.close()
    wait_for_events(security_log_path, "non_tls_connection")


def test_address_rate_limit_is_logged_and_enforced(net, security_log_path):
    guard = LockoutGuard(addr_limit=2, addr_window=60)
    server, host, port = net.start_server(lockout=guard)

    results = [net.register_attempt(port, dc.demo_username(f"rl{i}")) for i in range(4)]

    assert [r["success"] for r in results] == [True, True, False, False]
    for r in results[2:]:
        assert "too many requests" in r["reason"]
    assert len(wait_for_events(security_log_path, "address_rate_limited", count=2)) == 2


# --- security_alert envelope -------------------------------------------------

def test_client_sends_security_alert_on_tampered_message(net, security_log_path):
    server, host, port = net.start_server()
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    alice = net.register_client(port, alice_name, bob_name)
    bob = net.register_client(port, bob_name, alice_name)
    assert dc.establish_signed_handshake(alice, bob)

    # Feed bob a hand-built garbage ciphertext -- this test is about the
    # resulting security_alert, not the attack mechanism itself (that is
    # what tests/test_attack_lab.py and test_aes_gcm.py cover).
    bob._handle_chat({"type": "chat", "from": alice_name,
                      "nonce": b64(os.urandom(12)), "ciphertext": b64(b"x" * 16),
                      "tag": b64(b"y" * 16)})

    alerts = wait_for_events(security_log_path, "security_alert")
    assert alerts[-1]["reported_by"] == bob_name
    assert alerts[-1]["alert"] == "message_rejected"
    assert alerts[-1]["peer"] == alice_name
    assert "hello" not in open(security_log_path).read()


def test_client_sends_security_alert_on_handshake_abort(net, security_log_path):
    """Registers only BOB for real (connected to the real server, so his
    security_alert really reaches it); "alice" is a fabricated identity that
    never registers or connects. This deliberately avoids the real automatic
    handshake alice<->bob would otherwise race against -- see
    demo/run_mitm_handshake_demo.py and tests/test_handshake_auth.py for why
    a hand-built forged handshake_init needs an uncontested target."""
    server, host, port = net.start_server()
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    _, real_alice_pub = generate_keypair()
    attacker_priv, _ = generate_keypair()

    bob = net.register_client(port, bob_name, alice_name)
    bob.peer_public_key = real_alice_pub
    bob.peer_public_key_pem = serialize_public_key(real_alice_pub).decode("ascii")

    _, forged_pub = generate_ecdh_keypair()
    bob._handle_handshake_init({
        "type": "handshake_init", "from": alice_name, "to": bob_name,
        "pubkey": b64(forged_pub), "handshake_sig": b64(sign(attacker_priv, forged_pub))})

    assert bob.session_key is None
    alerts = wait_for_events(security_log_path, "security_alert")
    assert any(a["alert"] == "handshake_aborted" and a["reported_by"] == bob_name
               for a in alerts)


# --- full lockout flow end to end, including the PBKDF2-skip ----------------

def test_full_lockout_flow_end_to_end(net, security_log_path):
    guard = LockoutGuard(threshold=3, window=60, backoff_schedule=(1,))  # 1s lock
    server, host, port = net.start_server(lockout=guard)
    username = dc.demo_username("lockme")
    net.disconnect(server, net.register_client(port, username, "nobody"))

    results = [net.login_attempt(port, username, "wrong") for _ in range(3)]
    assert [r["success"] for r in results] == [False, False, False]
    assert results[0]["reason"] == "invalid username or password"
    assert results[2]["reason"] == "invalid username or password"  # generic even at the trigger

    with patch("server.user_store.verify_password") as spy:
        locked_attempt = net.login_attempt(port, username, "wrong-again")
    spy.assert_not_called()  # locked -> PBKDF2 never runs
    assert locked_attempt["success"] is False
    assert "locked" in locked_attempt["reason"]

    wait_for_events(security_log_path, "account_locked")
    wait_for_events(security_log_path, "lockout_rejected")

    time.sleep(1.2)  # the lock lasts 1s and was set before the attempt above
    final = net.login_attempt(port, username, dc.DEMO_PASSWORD)
    assert final["success"] is True
    wait_for_events(security_log_path, "user_login")
