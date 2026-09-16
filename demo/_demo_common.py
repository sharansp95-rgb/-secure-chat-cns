"""Shared plumbing for the demo/run_*.py scripts.

Not a demo itself -- each demo/run_*.py script imports this for the boring,
repeated bits (starting a real mini relay server, registering a real client
against it) so the run_*.py files can stay focused on the one attack/defense
scenario each is meant to demonstrate. This uses the actual project code
(server.server.ChatServer, client.client.SecureChatClient) over real TLS
sockets on localhost -- nothing here is a mock or a simulation of the
protocol, it's the real thing, pointed at an ephemeral local port so it
doesn't collide with any server you might already have running.
"""

import contextlib
import io
import os
import socket
import sys
import threading
import time
import uuid

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from auth.keystore import save_private_key  # noqa: E402
from client.client import (  # noqa: E402
    SecureChatClient,
    TLSSetupError,
    connect_tls,
    serialize_public_key,
)
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from server.server import CertsMissingError, ChatServer  # noqa: E402

DEMO_PASSWORD = "Demo-Password-1234!"


class Tee(io.TextIOBase):
    """Writes to both the real terminal and an in-memory buffer, so a demo
    step's narration is visible live (for the audience) while also being
    captured for this script's own pass/fail assertions afterward."""

    def __init__(self, real_stream):
        self._real = real_stream
        self.buffer = io.StringIO()

    def write(self, s):
        self._real.write(s)
        self._real.flush()
        self.buffer.write(s)
        return len(s)

    def flush(self):
        self._real.flush()


def banner(title):
    line = "=" * 70
    print(f"\n{line}\n{title}\n{line}")


def run_step(description, fn):
    """Run `fn()` while narrating `description`, teeing all of its stdout so
    it's both visible live and returned as text for this script to assert
    against. Returns fn()'s return value alongside the captured text."""
    print(f"\n--- {description} ---")
    tee = Tee(sys.stdout)
    with contextlib.redirect_stdout(tee):
        result = fn()
    return result, tee.buffer.getvalue()


def check(condition, pass_msg, fail_msg):
    """Print a clear PASS/FAIL line and return the condition, for a script
    to aggregate into its final exit code."""
    if condition:
        print(f"[PASS] {pass_msg}")
    else:
        print(f"[FAIL] {fail_msg}")
    return condition


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(host, port, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start_mini_relay(host="127.0.0.1"):
    """Start a real ChatServer (real TLS, using this project's own
    certs/server.crt + server.key) on a free ephemeral port, in a background
    thread. Requires certs to already exist -- run
    `python certs/generate_certs.py` first if they don't."""
    port = free_port()
    try:
        server = ChatServer(host, port)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        print("[!] This demo needs a real TLS cert. Run "
              "`python certs/generate_certs.py` once, then re-run this demo.")
        sys.exit(1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if not wait_for_port(host, port, timeout=5):
        print("[!] Mini relay server never started listening.")
        sys.exit(1)
    print(f"[*] Mini relay server listening on {host}:{port} (TLS)")
    return server, host, port


def demo_username(label):
    """A fresh, collision-free username for this demo run -- these demos
    register a real account against the real (gitignored, local) user store
    each time they run, so a unique suffix avoids 'username already taken'
    on a second run."""
    return f"demo_{label}_{uuid.uuid4().hex[:8]}"


def register_client(host, port, username, peer):
    """Connect over real TLS, register a fresh account (real RSA keypair,
    real PBKDF2-hashed password), and return the ready SecureChatClient.
    Equivalent to what client/client.py's interactive flow does, just
    without the interactive prompts."""
    try:
        sock = connect_tls(host, port)
    except TLSSetupError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    client = SecureChatClient(sock, username=username, peer=peer)
    threading.Thread(target=client.receive_loop, daemon=True).start()

    rsa_private_key, rsa_public_key = generate_rsa_keypair()
    public_key_pem = serialize_public_key(rsa_public_key).decode("ascii")
    client.register(username, DEMO_PASSWORD, public_key_pem=public_key_pem)
    result = client.auth_results.get(timeout=10)
    if not result or not result.get("success"):
        print(f"[!] Registration failed for {username}: "
              f"{result.get('reason') if result else 'no response'}")
        sys.exit(1)

    save_private_key(username, rsa_private_key)
    client.rsa_private_key = rsa_private_key
    return client


def establish_signed_handshake(client_a, client_b, timeout=5):
    """Drive a real, real-crypto ECDH handshake (signed per Phase 7a) to
    completion between two already-registered demo clients, deterministically
    (no reliance on roster/user_joined timing), and return True once both
    sides report a session key."""
    assert client_a.fetch_peer_public_key(timeout=timeout), \
        f"{client_a.username} could not fetch {client_a.peer}'s public key"
    assert client_b.fetch_peer_public_key(timeout=timeout), \
        f"{client_b.username} could not fetch {client_b.peer}'s public key"

    # Same deterministic tie-break the real client uses: lower username
    # initiates. Whichever of A/B that is, initiate from that side.
    initiator, responder = (
        (client_a, client_b) if client_a.username < client_b.username
        else (client_b, client_a)
    )
    initiator.initiate_handshake()

    deadline = time.time() + timeout
    while time.time() < deadline:
        if client_a.session_key is not None and client_b.session_key is not None:
            return True
        time.sleep(0.05)
    return False
