"""Secure chat client: login/registration + ECDH handshake + AES-GCM messaging.

Phase 4 adds an authentication step in front of everything else: on startup
the user registers a new account or logs into an existing one (username +
password, password read with getpass so it is never echoed to the
terminal). Only after the server confirms success does the client proceed to
the existing Phase 3 flow: an ECDH (X25519) handshake with a chosen peer
(see crypto_engine/dh_exchange.py and the README's "How the handshake works"
section), after which every chat message is encrypted with
crypto_engine/aes_gcm.py before it is sent, and decrypted after it is
received -- the server only ever sees the encrypted chat envelope.

SECURITY NOTE: the register/login envelope carries the password itself (so
the server can hash/check it) over the plain TCP socket -- that leg is not
yet encrypted at this phase. See the note in server/server.py and the
README's Phase 4 section: this is a known, deliberate gap closed by Phase 6
(TLS), not something patched around here.

Handshake initiation rule: to avoid both sides racing to start a handshake at
once, only the client whose username sorts lexicographically *lower* sends
the first handshake_init; the other client only responds when it receives
one. This is a local, deterministic tie-break -- it carries no security
weight, it just avoids a duplicate handshake.

Wire format: one JSON object per line, matching server/server.py. Binary
fields (public keys, nonce, ciphertext, tag) are base64-encoded for JSON.
"""

import argparse
import base64
import getpass
import json
import os
import queue
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_engine.aes_gcm import DecryptionError, decrypt, encrypt  # noqa: E402
from crypto_engine.dh_exchange import compute_shared_key, generate_keypair  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii"))


def read_password(prompt="Password: "):
    """Read a password without echoing it, when a real terminal is attached.

    On a real terminal this is exactly getpass.getpass(). When stdin is
    redirected/piped (e.g. a scripted demo or test harness), Windows'
    getpass implementation reads straight from the console via msvcrt and
    hangs forever rather than falling back -- unlike Unix's getpass, which
    already degrades gracefully to a plain stdin read in that case. This
    mirrors that same graceful fallback on both platforms.
    """
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    return line.rstrip("\n") if line else ""


class SecureChatClient:
    def __init__(self, sock, username, peer):
        self.sock = sock
        self.username = username
        self.peer = peer
        self.stop_event = threading.Event()

        # Results of "register_result"/"login_result" envelopes, handed from
        # the receiver thread to whoever is blocked waiting in authenticate().
        self.auth_results = queue.Queue()

        # Handshake / session state, guarded by _lock since the receiver
        # thread and the send loop both touch it.
        self._lock = threading.Lock()
        self._pending_private_key = None  # our transient ECDH private key
        self.session_key = None  # 32-byte AES key once handshake completes
        self._handshake_started = False
        self._outgoing_queue = []  # messages typed before the key was ready

    def send_envelope(self, envelope):
        try:
            self.sock.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
        except OSError:
            self.stop_event.set()

    # --- authentication --------------------------------------------------

    def register(self, username, password):
        self.send_envelope({"type": "register", "username": username, "password": password})

    def login(self, username, password):
        self.send_envelope({"type": "login", "username": username, "password": password})

    # --- handshake -----------------------------------------------------

    def initiate_handshake(self):
        with self._lock:
            if self._handshake_started or self.session_key is not None:
                return
            self._handshake_started = True
            private_key, public_bytes = generate_keypair()
            self._pending_private_key = private_key

        print(f"\r[*] Starting key exchange with {self.peer}...\n> ", end="", flush=True)
        self.send_envelope({
            "type": "handshake_init",
            "from": self.username,
            "to": self.peer,
            "pubkey": b64(public_bytes),
        })

    def _handle_handshake_init(self, envelope):
        peer_pub = unb64(envelope["pubkey"])
        private_key, public_bytes = generate_keypair()
        session_key = compute_shared_key(private_key, peer_pub)
        # Private key and raw shared secret are never retained past this
        # point -- only the derived session key is kept.
        del private_key

        self.send_envelope({
            "type": "handshake_response",
            "from": self.username,
            "to": self.peer,
            "pubkey": b64(public_bytes),
        })
        self._finish_handshake(session_key)

    def _handle_handshake_response(self, envelope):
        peer_pub = unb64(envelope["pubkey"])
        with self._lock:
            private_key = self._pending_private_key
            self._pending_private_key = None
        if private_key is None:
            return  # response we didn't ask for; ignore
        session_key = compute_shared_key(private_key, peer_pub)
        del private_key
        self._finish_handshake(session_key)

    def _finish_handshake(self, session_key):
        with self._lock:
            self.session_key = session_key
            queued = self._outgoing_queue
            self._outgoing_queue = []
        print(f"\r[*] Secure session established with {self.peer} "
              f"(AES-256-GCM key derived via ECDH).\n> ", end="", flush=True)
        for text in queued:
            self._encrypt_and_send(text)

    # --- chat ------------------------------------------------------------

    def _encrypt_and_send(self, text):
        with self._lock:
            key = self.session_key
        box = encrypt(key, text.encode("utf-8"))
        self.send_envelope({
            "type": "chat",
            "from": self.username,
            "to": self.peer,
            "nonce": b64(box["nonce"]),
            "ciphertext": b64(box["ciphertext"]),
            "tag": b64(box["tag"]),
        })

    def send_message(self, text):
        with self._lock:
            ready = self.session_key is not None
            if not ready:
                self._outgoing_queue.append(text)
        if not ready:
            self.initiate_handshake()
            print("[*] Message queued until the secure session is ready.")
            return
        self._encrypt_and_send(text)

    def _handle_chat(self, envelope):
        with self._lock:
            key = self.session_key
        if key is None:
            print(f"\r[!] Received an encrypted message from {envelope.get('from')} "
                  f"before a session key was established -- dropped.\n> ", end="", flush=True)
            return
        try:
            plaintext = decrypt(
                key,
                unb64(envelope["nonce"]),
                unb64(envelope["ciphertext"]),
                unb64(envelope["tag"]),
            )
        except (DecryptionError, KeyError, ValueError):
            print(f"\r[!] WARNING: message from {envelope.get('from')} failed "
                  f"authentication (tampered or wrong key) -- discarded.\n> ",
                  end="", flush=True)
            return
        sender = envelope.get("from", self.peer)
        print(f"\r{sender}: {plaintext.decode('utf-8', errors='replace')}\n> ",
              end="", flush=True)

    # --- receive loop ------------------------------------------------------

    def receive_loop(self):
        try:
            with self.sock.makefile("r", encoding="utf-8", newline="\n") as stream:
                for line in stream:
                    if self.stop_event.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        envelope = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    etype = envelope.get("type")
                    if etype in ("register_result", "login_result"):
                        self.auth_results.put(envelope)
                    elif etype == "system":
                        print(f"\r{envelope.get('text', '')}\n> ", end="", flush=True)
                    elif etype == "roster":
                        if self.peer in envelope.get("users", []) and self.username < self.peer:
                            self.initiate_handshake()
                    elif etype == "user_joined":
                        if envelope.get("username") == self.peer and self.username < self.peer:
                            self.initiate_handshake()
                    elif etype == "handshake_init" and envelope.get("from") == self.peer:
                        self._handle_handshake_init(envelope)
                    elif etype == "handshake_response" and envelope.get("from") == self.peer:
                        self._handle_handshake_response(envelope)
                    elif etype == "chat" and envelope.get("from") == self.peer:
                        self._handle_chat(envelope)
        except (OSError, ValueError):
            pass
        finally:
            if not self.stop_event.is_set():
                print("\r[!] Disconnected from server.", flush=True)
            self.stop_event.set()
            # Unblock anyone still waiting on an auth result.
            self.auth_results.put(None)


def authenticate(client):
    """Interactively register or log in over an already-connected client.

    Retries on failure (wrong password, username taken, etc.) until success,
    the user gives up, or the connection drops. Returns True on success.
    """
    while not client.stop_event.is_set():
        choice = input("1) Register  2) Login  (or 'q' to quit): ").strip().lower()
        if choice in ("q", "quit"):
            return False
        if choice not in ("1", "2", "register", "login"):
            print("Please enter 1, 2, or q.")
            continue

        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        password = read_password("Password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        client.username = username
        if choice in ("1", "register"):
            client.register(username, password)
        else:
            client.login(username, password)

        result = client.auth_results.get()
        if result is None:
            print("[!] Connection lost during authentication.")
            return False
        if result.get("success"):
            print(f"[*] {result.get('reason', 'Success.')}")
            return True
        print(f"[!] {result.get('reason', 'Authentication failed.')} Please try again.")
    return False


def main():
    parser = argparse.ArgumentParser(description="Secure login + ECDH + AES-GCM chat client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--username", help="skip the username prompt during register/login")
    parser.add_argument("--password", help="skip the password prompt (testing/demo only; "
                                             "prefer the interactive getpass prompt normally)")
    parser.add_argument("--register", action="store_true",
                         help="register a new account instead of logging in "
                              "(used with --username/--password to skip prompts)")
    parser.add_argument("--peer", help="username of the peer to chat securely with")
    args = parser.parse_args()

    peer = args.peer or input("Peer username to chat securely with: ").strip()
    if not peer:
        print("A peer username is required.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except OSError as exc:
        print(f"[!] Could not connect to {args.host}:{args.port} -- {exc}")
        sys.exit(1)

    client = SecureChatClient(sock, username=None, peer=peer)
    threading.Thread(target=client.receive_loop, daemon=True).start()

    if args.username and args.password:
        # Non-interactive path, for scripted demos/tests only.
        client.username = args.username
        if args.register:
            client.register(args.username, args.password)
        else:
            client.login(args.username, args.password)
        result = client.auth_results.get()
        authenticated = bool(result and result.get("success"))
        if result:
            print(f"[{'*' if authenticated else '!'}] {result.get('reason')}")
    else:
        authenticated = authenticate(client)

    if not authenticated or client.stop_event.is_set():
        print("[!] Not authenticated -- exiting.")
        client.stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        sys.exit(1)

    if peer == client.username:
        print("Peer must be a different user than yourself.")
        client.stop_event.set()
        sock.close()
        sys.exit(1)

    print(f"[*] Logged in as {client.username}. Chatting securely with {peer}. "
          f"Type a message and press Enter (Ctrl-C to quit).")

    try:
        while not client.stop_event.is_set():
            try:
                text = input("> ")
            except EOFError:
                break
            if not text.strip():
                continue
            if client.stop_event.is_set():
                break
            client.send_message(text)
    except KeyboardInterrupt:
        print()
    finally:
        client.stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("[*] Disconnected.")


if __name__ == "__main__":
    main()
