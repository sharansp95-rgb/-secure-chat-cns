"""Tests for Stage D's security event log, its server.py call sites, and the
client-side security_alert envelope.

Covers: events are valid JSON lines with the expected fields and carry no
plaintext/password/key material; security_alert envelopes are logged
correctly; and the full login-lockout flow end to end through real TLS
clients, including that a locked attempt never reaches PBKDF2.
"""

import json
import os
import socket
import sys
import threading
import time
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))

import _demo_common as dc  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import generate_keypair, serialize_public_key  # noqa: E402
from server.lockout import LockoutGuard  # noqa: E402
from server.security_log import log_event, read_events  # noqa: E402
from server.server import CertsMissingError, ChatServer  # noqa: E402

SENSITIVE_SUBSTRINGS = ("password", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                        "session_key", "plaintext")


def start_server(tmp_path, monkeypatch, lockout=None, lab_mode=False):
    """Starts a real ChatServer with its log_event calls redirected to a
    per-test tmp_path file, via pytest's monkeypatch (auto-restored after
    the test, so this never leaks into other tests sharing this process --
    unlike a manual save/overwrite that forgets to restore)."""
    port = dc.free_port()
    try:
        server = ChatServer("127.0.0.1", port, lab_mode=lab_mode,
                            lockout=lockout or LockoutGuard())
    except CertsMissingError as exc:
        pytest.skip(f"certs not generated: {exc}")
    log_path = tmp_path / "events.jsonl"
    import server.server as server_module
    real_log_event = server_module.log_event  # the true original, captured fresh

    def redirected(event, path=None, **fields):
        return real_log_event(event, path=str(log_path), **fields)

    monkeypatch.setattr(server_module, "log_event", redirected)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    assert dc.wait_for_port("127.0.0.1", port, timeout=5)
    return server, "127.0.0.1", port, log_path


def events_of(log_path, event_type):
    return [e for e in read_events(str(log_path)) if e["event"] == event_type]


def disconnect_and_wait(server, client, timeout=5):
    """Cleanly close `client`'s connection and block until the SERVER has
    actually removed it from its roster -- a bare time.sleep() after
    close() is a race (TLS teardown + the server's blocking read noticing
    EOF are not instant), and a login attempt against a username the
    server still considers online gets "already logged in elsewhere"
    instead of exercising the password-verification path these tests
    target."""
    username = client.username
    client.stop_event.set()
    try:
        client.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client.sock.close()
    deadline = time.time() + timeout
    while time.time() < deadline:
        with server._lock:
            if username not in server.clients:
                return
        time.sleep(0.02)
    raise AssertionError(f"server never removed {username} from its roster")


# --- event log mechanics ------------------------------------------------------

def test_log_event_writes_a_valid_json_line(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    log_event("user_login", path=str(path), username="alice", from_addr="127.0.0.1")
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "user_login"
    assert record["username"] == "alice"
    assert isinstance(record["ts"], float)


def test_multiple_events_are_separate_lines_and_all_parse(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    for i in range(5):
        log_event("failed_login", path=str(path), username=f"user{i}")
    events = read_events(str(path))
    assert len(events) == 5
    assert [e["username"] for e in events] == [f"user{i}" for i in range(5)]


def test_read_events_on_missing_file_returns_empty_list(tmp_path, monkeypatch):
    assert read_events(str(tmp_path / "nope.jsonl")) == []


# --- end-to-end: register/login produce the right events, no secrets --------

def test_register_and_login_produce_expected_events_with_no_secrets(tmp_path, monkeypatch):
    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    username = dc.demo_username("evt")
    client = dc.register_client(host, port, username, "nobody")
    client.stop_event.set()
    client.sock.close()
    time.sleep(0.2)

    registered = events_of(log_path, "user_registered")
    assert registered and registered[0]["username"] == username
    assert registered[0]["from_addr"] == "127.0.0.1"

    raw = log_path.read_text()
    for secret in SENSITIVE_SUBSTRINGS:
        assert secret not in raw
    assert dc.DEMO_PASSWORD not in raw


def test_failed_login_is_logged_with_no_password(tmp_path, monkeypatch):
    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    username = dc.demo_username("evt")
    registrant = dc.register_client(host, port, username, "nobody")
    disconnect_and_wait(server, registrant)

    sock = dc.connect_tls(host, port)
    c = dc.SecureChatClient(sock, username=None, peer="x")
    threading.Thread(target=c.receive_loop, daemon=True).start()
    c.login(username, "definitely-the-wrong-password")
    result = c.auth_results.get(timeout=10)
    assert result["success"] is False
    c.stop_event.set()
    sock.close()
    time.sleep(0.2)

    failures = events_of(log_path, "failed_login")
    assert failures and failures[0]["username"] == username
    assert "definitely-the-wrong-password" not in log_path.read_text()


def test_malformed_envelope_is_logged(tmp_path, monkeypatch):
    import socket
    import ssl

    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    username = dc.demo_username("evt")
    client = dc.register_client(host, port, username, "nobody")
    client.sock.sendall(b"{not valid json at all\n")
    time.sleep(0.3)
    events = events_of(log_path, "malformed_envelope")
    assert events and events[0]["from_user"] == username
    client.stop_event.set()
    client.sock.close()


def test_non_tls_connection_is_logged(tmp_path, monkeypatch):
    import socket

    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    raw = socket.create_connection((host, port), timeout=3)
    raw.sendall(b"not tls at all\n")
    try:
        raw.recv(16)
    except OSError:
        pass
    raw.close()
    time.sleep(0.3)
    assert events_of(log_path, "non_tls_connection")


def test_address_rate_limit_is_logged_and_enforced(tmp_path, monkeypatch):
    guard = LockoutGuard(addr_limit=2, addr_window=60)
    server, host, port, log_path = start_server(tmp_path, monkeypatch, lockout=guard)

    results = []
    for i in range(4):
        sock = dc.connect_tls(host, port)
        c = dc.SecureChatClient(sock, username=None, peer="x")
        threading.Thread(target=c.receive_loop, daemon=True).start()
        c.register(dc.demo_username(f"rl{i}"), dc.DEMO_PASSWORD, public_key_pem=None)
        result = c.auth_results.get(timeout=10)
        results.append(result)
        c.stop_event.set()
        sock.close()

    assert [r["success"] for r in results] == [True, True, False, False]
    for r in results[2:]:
        assert "too many requests" in r["reason"]
    assert len(events_of(log_path, "address_rate_limited")) == 2


# --- security_alert envelope -------------------------------------------------

def test_client_sends_security_alert_on_tampered_message(tmp_path, monkeypatch):
    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    alice = dc.register_client(host, port, alice_name, bob_name)
    bob = dc.register_client(host, port, bob_name, alice_name)
    assert dc.establish_signed_handshake(alice, bob)

    # Directly feed bob a hand-built, garbage ciphertext -- this test is
    # about the resulting security_alert, not the attack mechanism itself
    # (that's what tests/test_attack_lab.py and test_aes_gcm.py cover).
    from client.client import b64
    bad_env = {"type": "chat", "from": alice_name,
              "nonce": b64(os.urandom(12)), "ciphertext": b64(b"x" * 16),
              "tag": b64(b"y" * 16)}
    bob._handle_chat(bad_env)
    time.sleep(0.3)

    alerts = events_of(log_path, "security_alert")
    assert alerts
    assert alerts[-1]["reported_by"] == bob_name
    assert alerts[-1]["alert"] == "message_rejected"
    assert alerts[-1]["peer"] == alice_name
    raw_log = log_path.read_text()
    assert "hello" not in raw_log


def test_client_sends_security_alert_on_handshake_abort(tmp_path, monkeypatch):
    """Registers only BOB for real (connected to the real server, so his
    security_alert really reaches it); "alice" is a fabricated identity that
    never registers or connects. This deliberately avoids the real
    automatic handshake alice<->bob would otherwise race against -- see
    demo/run_mitm_handshake_demo.py and tests/test_handshake_auth.py for
    why a hand-built forged handshake_init needs an uncontested target."""
    server, host, port, log_path = start_server(tmp_path, monkeypatch)
    alice_name = dc.demo_username("alice")
    bob_name = dc.demo_username("bob")
    real_alice_priv, real_alice_pub = generate_keypair()
    attacker_priv, _ = generate_keypair()

    bob = dc.register_client(host, port, bob_name, alice_name)
    bob.peer_public_key = real_alice_pub
    bob.peer_public_key_pem = serialize_public_key(real_alice_pub).decode("ascii")

    _, forged_pub = generate_ecdh_keypair()
    from crypto_engine.signatures import sign
    from client.client import b64
    forged = {"type": "handshake_init", "from": alice_name, "to": bob_name,
             "pubkey": b64(forged_pub), "handshake_sig": b64(sign(attacker_priv, forged_pub))}
    bob._handle_handshake_init(forged)
    time.sleep(0.3)

    assert bob.session_key is None
    alerts = events_of(log_path, "security_alert")
    assert any(a["alert"] == "handshake_aborted" and a["reported_by"] == bob_name
              for a in alerts)


# --- full lockout flow end to end, including the PBKDF2-skip ----------------

def test_full_lockout_flow_end_to_end(tmp_path, monkeypatch):
    guard = LockoutGuard(threshold=3, window=60, backoff_schedule=(1,))  # 1s lock, fast test
    server, host, port, log_path = start_server(tmp_path, monkeypatch, lockout=guard)
    username = dc.demo_username("lockme")
    registrant = dc.register_client(host, port, username, "nobody")
    disconnect_and_wait(server, registrant)

    def try_login(password):
        sock = dc.connect_tls(host, port)
        c = dc.SecureChatClient(sock, username=None, peer="x")
        threading.Thread(target=c.receive_loop, daemon=True).start()
        c.login(username, password)
        result = c.auth_results.get(timeout=10)
        c.stop_event.set()
        sock.close()
        return result

    results = [try_login("wrong") for _ in range(3)]
    assert [r["success"] for r in results] == [False, False, False]
    assert results[0]["reason"] == "invalid username or password"
    assert results[2]["reason"] == "invalid username or password"  # generic even at the trigger

    with patch("server.user_store.verify_password") as spy:
        locked_attempt = try_login("wrong-again")
    spy.assert_not_called()  # locked -> PBKDF2 never runs
    assert locked_attempt["success"] is False
    assert "locked" in locked_attempt["reason"]

    assert events_of(log_path, "account_locked")
    assert events_of(log_path, "lockout_rejected")

    time.sleep(1.2)  # let the 1s backoff expire
    final = try_login(dc.DEMO_PASSWORD)
    assert final["success"] is True
    assert events_of(log_path, "user_login")
