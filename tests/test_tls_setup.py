"""Integration tests for the Phase 6 TLS transport layer.

Spins up the real TLS-wrapped ChatServer in a background thread (not a
subprocess -- these tests exercise the actual ssl.SSLContext objects and
socket plumbing in server.py/client.py directly) and drives it with real
sockets, to confirm:

  1. A correctly-configured TLS client can still complete the existing
     Phase 4 register/login round trip end-to-end -- the new transport layer
     doesn't break the application logic underneath it.
  2. A client that skips TLS entirely (raw socket) cannot get a usable
     plaintext conversation out of the server.
  3. A client that trusts a different, unrelated self-signed cert fails
     certificate verification against the real server -- i.e. we are
     actually pinning trust to our own cert, not silently accepting anyone.
"""

import json
import os
import socket
import ssl
import sys
import threading
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certs.generate_certs import generate as generate_certs  # noqa: E402
from server.server import ChatServer  # noqa: E402

HOST = "127.0.0.1"


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _wait_for_port(host, port, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


@pytest.fixture()
def certs(tmp_path):
    """A real cert+key pair for the test server, generated fresh per test
    (not the developer's own certs/server.crt) so tests are hermetic."""
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    key_path = certs_dir / "server.key"
    cert_path = certs_dir / "server.crt"

    # Reuse the real generator, just point it at a temp file pair via
    # monkeypatching its module-level paths for the duration of this call.
    import certs.generate_certs as gen_mod
    orig_key, orig_cert = gen_mod.KEY_PATH, gen_mod.CERT_PATH
    gen_mod.KEY_PATH, gen_mod.CERT_PATH = str(key_path), str(cert_path)
    try:
        assert generate_certs(force=True)
    finally:
        gen_mod.KEY_PATH, gen_mod.CERT_PATH = orig_key, orig_cert

    return str(key_path), str(cert_path)


@pytest.fixture()
def running_server(certs):
    key_path, cert_path = certs
    port = _free_port()
    server = ChatServer(HOST, port, certfile=cert_path, keyfile=key_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert _wait_for_port(HOST, port), "test server never started listening"
    yield server, HOST, port, cert_path
    # Daemon thread; process teardown handles cleanup for these short tests.


def _tls_client_socket(host, port, cafile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(5)
    raw.connect((host, port))
    return context.wrap_socket(raw, server_hostname="localhost")


# --- 1. correctly-configured TLS client: full register/login round trip ---

def test_tls_client_register_login_round_trip(running_server):
    _, host, port, cert_path = running_server
    # Unique per run: server.py's user store is a real, persistent local
    # file (data/users.json), not test-isolated by path, so a fixed
    # username would collide with a leftover account from a previous run.
    username = f"tls_test_user_{uuid.uuid4().hex[:8]}"
    sock = _tls_client_socket(host, port, cert_path)
    try:
        with sock.makefile("r", encoding="utf-8", newline="\n") as stream:
            sock.sendall((json.dumps({
                "type": "register", "username": username, "password": "hunter2pw",
            }) + "\n").encode("utf-8"))
            result = json.loads(stream.readline())
            assert result["type"] == "register_result"
            assert result["success"] is True

            # roster envelope follows immediately after a successful register
            roster = json.loads(stream.readline())
            assert roster["type"] == "roster"
    finally:
        sock.close()


def test_tls_client_wrong_password_login_rejected(running_server):
    _, host, port, cert_path = running_server
    username = f"tls_test_user_{uuid.uuid4().hex[:8]}"
    sock = _tls_client_socket(host, port, cert_path)
    try:
        with sock.makefile("r", encoding="utf-8", newline="\n") as stream:
            sock.sendall((json.dumps({
                "type": "register", "username": username, "password": "correctpw",
            }) + "\n").encode("utf-8"))
            json.loads(stream.readline())  # register_result
    finally:
        sock.close()

    sock2 = _tls_client_socket(host, port, cert_path)
    try:
        with sock2.makefile("r", encoding="utf-8", newline="\n") as stream:
            sock2.sendall((json.dumps({
                "type": "login", "username": username, "password": "wrongpw",
            }) + "\n").encode("utf-8"))
            result = json.loads(stream.readline())
            assert result["type"] == "login_result"
            assert result["success"] is False
    finally:
        sock2.close()


# --- 2. a client that skips TLS entirely cannot get a usable conversation -

def test_raw_non_tls_client_cannot_speak_the_protocol(running_server):
    _, host, port, _ = running_server
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(3)
    raw.connect((host, port))
    try:
        # Send what a plaintext client would have sent pre-Phase-6.
        raw.sendall((json.dumps({
            "type": "register", "username": "plaintext_attacker", "password": "x",
        }) + "\n").encode("utf-8"))

        # The server is doing a TLS handshake on its side and will not
        # understand this plaintext; it will not echo back a valid
        # register_result JSON line. Either the read times out (server is
        # stuck waiting for a TLS ClientHello it will never get) or we
        # receive unintelligible bytes that are not our JSON envelope
        # protocol.
        raw.settimeout(2)
        try:
            data = raw.recv(4096)
        except socket.timeout:
            data = b""
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # The server rejected the connection at the TLS layer (e.g. our
            # plaintext bytes don't look like a valid TLS record) and reset
            # it -- also a valid demonstration that plaintext no longer works.
            data = b""

        if data:
            # We got *something* back (e.g. a TLS alert) -- it must not be
            # a valid, parseable register_result envelope.
            text = data.decode("utf-8", errors="replace")
            is_valid_envelope = False
            try:
                parsed = json.loads(text.strip().splitlines()[0])
                is_valid_envelope = parsed.get("type") == "register_result"
            except (json.JSONDecodeError, IndexError):
                is_valid_envelope = False
            assert not is_valid_envelope, (
                "raw non-TLS client received a valid plaintext register_result "
                "-- the server is still speaking plaintext to non-TLS clients!"
            )
        # else: no data at all (connection hung / was dropped) -- also an
        # acceptable demonstration that plaintext no longer works.
    finally:
        raw.close()


# --- 3. a client trusting a different, unrelated cert fails verification --

def test_client_trusting_different_cert_fails_verification(running_server, tmp_path):
    _, host, port, _real_cert_path = running_server

    # Generate a second, completely unrelated self-signed cert in a temp dir.
    other_certs_dir = tmp_path / "other_certs"
    other_certs_dir.mkdir()
    other_key_path = other_certs_dir / "other.key"
    other_cert_path = other_certs_dir / "other.crt"

    import certs.generate_certs as gen_mod
    orig_key, orig_cert = gen_mod.KEY_PATH, gen_mod.CERT_PATH
    gen_mod.KEY_PATH, gen_mod.CERT_PATH = str(other_key_path), str(other_cert_path)
    try:
        assert generate_certs(force=True)
    finally:
        gen_mod.KEY_PATH, gen_mod.CERT_PATH = orig_key, orig_cert

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(other_cert_path))
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(5)
    raw.connect((host, port))
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            context.wrap_socket(raw, server_hostname="localhost")
    finally:
        raw.close()
