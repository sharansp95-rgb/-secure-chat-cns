"""Shared fixtures for every test that starts a real server.

Why this exists (the flaky-test post-mortem, in one place)
-----------------------------------------------------------
Several integration tests intermittently timed out waiting for a login /
registration reply. The root cause was NOT test plumbing: the product shared
one ssl.SSLSocket between a reader thread and writer threads, which is not
thread-safe (see transport/locked_tls.py -- fixed there, and verified at 0
failures in 400 stress runs vs 46/400 before). These fixtures remove the
remaining ways a test could still be non-deterministic:

  * Ephemeral ports done right: servers bind port 0 and report the REAL port
    (ChatServer.listen()), instead of free_port() -- "close it, hope nobody
    grabs it, bind it later".
  * No readiness polling: listen() has already returned before a client is
    created, so there is nothing to wait for (and no stray raw "probe"
    connections generating spurious TLS-handshake failures).
  * Guaranteed teardown: every client and server a test creates is closed
    and joined by the fixture, even when the test fails, so no listening
    socket or thread leaks into the next test.
  * Fresh state per test: each server gets its own LockoutGuard, and the
    user store, private-key directory and security-event log are redirected
    to the test's tmp_path -- no carry-over between tests, and the
    developer's real data/ and logs/ are never touched.
  * Realistic timeouts: AUTH_TIMEOUT is generous because a registration or
    login does PBKDF2 at 200,000 iterations, which can take a while on a
    loaded machine; a timeout here means a genuine hang, not "slow".
"""

import functools
import os
import socket
import sys
import tempfile
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))

import _demo_common as dc  # noqa: E402
import client.client as client_module  # noqa: E402
import server.security_log as security_log  # noqa: E402
import server.server as server_module  # noqa: E402
from server.lockout import LockoutGuard  # noqa: E402

HOST = "127.0.0.1"
AUTH_TIMEOUT = 20  # seconds; see module docstring


# ---------------------------------------------------------------------------
# Session-scoped TLS certificates -- generated ONCE, used by every test.
# Tests must never read or write the real certs/ directory.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True, scope="session")
def _test_certs():
    """Generate a throwaway cert+key into a temp dir and point every module's
    default cert/key path at it for the entire test session.

    This makes `pytest` work on a fresh clone (where certs/ contains no .crt
    or .key) without requiring the developer to run generate_certs.py first.
    """
    import certs.generate_certs as gen_mod

    tmpdir = tempfile.mkdtemp(prefix="cns_test_certs_")
    key_path = os.path.join(tmpdir, "server.key")
    cert_path = os.path.join(tmpdir, "server.crt")

    orig_key, orig_cert = gen_mod.KEY_PATH, gen_mod.CERT_PATH
    gen_mod.KEY_PATH, gen_mod.CERT_PATH = key_path, cert_path
    try:
        gen_mod.generate(force=True)
    finally:
        gen_mod.KEY_PATH, gen_mod.CERT_PATH = orig_key, orig_cert

    # Resolve paths at use time through an environment variable, rather than
    # patching imported modules.  That makes script-mode subprocess tests and
    # demo helpers inherit the same throwaway certificate directory.
    old_cert_dir = os.environ.get("SECURECHAT_CERT_DIR")
    os.environ["SECURECHAT_CERT_DIR"] = tmpdir

    yield cert_path, key_path

    if old_cert_dir is None:
        os.environ.pop("SECURECHAT_CERT_DIR", None)
    else:
        os.environ["SECURECHAT_CERT_DIR"] = old_cert_dir

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Per-test private user store, key directory and security log."""
    store = str(tmp_path / "users.json")
    keys_dir = str(tmp_path / "keys")
    for name in ("register_user", "verify_user", "get_public_key"):
        monkeypatch.setattr(server_module, name,
                            functools.partial(getattr(server_module, name), path=store))
    for module in (client_module, dc):
        monkeypatch.setattr(module, "save_private_key",
                            functools.partial(module.save_private_key, keys_dir=keys_dir))
    monkeypatch.setattr(client_module, "load_private_key",
                        functools.partial(client_module.load_private_key, keys_dir=keys_dir))

    log_path = str(tmp_path / "security_events.jsonl")
    real_log_event = security_log.log_event
    monkeypatch.setattr(server_module, "log_event",
                        lambda event, **fields: real_log_event(event, path=log_path, **fields))
    return log_path


@pytest.fixture()
def security_log_path(isolated_state):
    """Path of this test's security-event log (see server.security_log)."""
    return isolated_state


class NetEnv:
    """Starts servers/clients for one test and tears all of them down."""

    def __init__(self):
        self._servers = []
        self._clients = []

    # -- servers ------------------------------------------------------------

    def start_server(self, server_cls=None, lab_mode=False, lockout=None, **kwargs):
        """Start a real TLS ChatServer on an OS-chosen free port. Returns
        (server, host, port); the server is already accepting connections."""
        server_cls = server_cls or server_module.ChatServer
        server = server_cls(HOST, 0, lab_mode=lab_mode,
                            lockout=lockout or LockoutGuard(), **kwargs)
        port = server.listen()
        thread = threading.Thread(target=server.serve_forever, daemon=True,
                                  name=f"test-server-{port}")
        thread.start()
        self._servers.append((server, thread))
        return server, HOST, port

    # -- clients ------------------------------------------------------------

    def track(self, client):
        self._clients.append(client)
        return client

    def register_client(self, port, username, peer, event_callback=None):
        """Register `username` (real RSA identity, real PBKDF2 password)
        against the server on `port` and return the ready client. Pass
        `event_callback` to see events from the very first one (a callback
        attached afterwards can miss events that fire right after login)."""
        return self.track(dc.register_client(HOST, port, username, peer,
                                             event_callback=event_callback))

    def _auth_attempt(self, port, kind, username, password):
        sock = client_module.connect_tls(HOST, port)
        c = client_module.SecureChatClient(sock, username=None, peer="x")
        threading.Thread(target=c.receive_loop, daemon=True).start()
        try:
            getattr(c, kind)(username, password, **({"public_key_pem": None}
                                                    if kind == "register" else {}))
            result = c.auth_results.get(timeout=AUTH_TIMEOUT)
        finally:
            _close_client(c)
        assert result is not None, "connection dropped before the server answered"
        return result

    def login_attempt(self, port, username, password):
        """One real login over a fresh TLS connection; returns the server's
        login_result envelope. The connection is closed afterwards."""
        return self._auth_attempt(port, "login", username, password)

    def register_attempt(self, port, username, password=dc.DEMO_PASSWORD):
        """One real registration over a fresh TLS connection (no RSA key
        stored); returns the register_result envelope."""
        return self._auth_attempt(port, "register", username, password)

    def disconnect(self, server, client, timeout=10):
        """Close `client` and block until `server` has really removed it from
        its roster (a bare sleep() is a race; a login against a username the
        server still thinks is online gets 'already logged in elsewhere')."""
        _close_client(client)
        wait_until_offline(server, client.username, timeout)

    # -- teardown -------------------------------------------------------------

    def close_all(self):
        for c in self._clients:
            _close_client(c)
        for server, thread in self._servers:
            server.shutdown()
        for server, thread in self._servers:
            thread.join(timeout=5)
            assert not thread.is_alive(), "test server thread did not stop"


def wait_until_offline(server, username, timeout=10):
    """Block until `server` no longer lists `username` as connected."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with server._lock:
            if username not in server.clients:
                return
        time.sleep(0.01)
    raise AssertionError(f"server never removed {username} from its roster")


def _close_client(client):
    client.stop_event.set()
    try:
        client.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client.sock.close()


@pytest.fixture()
def net():
    env = NetEnv()
    try:
        yield env
    finally:
        env.close_all()


def wait_for_events(log_path, event_type, count=1, timeout=10):
    """Poll the security-event log until `count` events of `event_type`
    exist, and return them. The server logs AFTER it replies to the client,
    so reading the file immediately after a client call is a race; a
    timeout here means the event genuinely never happened."""
    from server.security_log import read_events
    deadline = time.time() + timeout
    while True:
        found = [e for e in read_events(log_path) if e["event"] == event_type]
        if len(found) >= count:
            return found
        if time.time() > deadline:
            raise AssertionError(
                f"expected {count} '{event_type}' event(s) within {timeout}s, "
                f"found {len(found)}")
        time.sleep(0.02)


@pytest.fixture(autouse=True)
def _finalize_tk_objects_on_the_main_thread():
    """Collect garbage right after every test, on the main thread.

    A destroyed Tk window leaves tkinter objects (Variables, ...) in reference cycles. If
    the garbage collector happens to run later on ANOTHER thread (e.g. a chat server
    thread in a networking test), tkinter finalises them there and Tcl aborts the whole
    process ("Tcl_AsyncDelete: async handler deleted by the wrong thread"; seen as exit
    code 133). Collecting here keeps that from ever happening."""
    yield
    import gc
    gc.collect()
