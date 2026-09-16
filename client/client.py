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

Phase 6 wraps the whole connection in TLS before anything -- including the
first register/login envelope -- is sent, closing the plaintext-on-the-wire
gap noted above. The client verifies the server's certificate against our
own self-signed CA (certs/server.crt, generated locally by
certs/generate_certs.py) via load_verify_locations, rather than disabling
verification -- so this is a real trust check, not just "encrypted but to
anyone." TLS is a transport-layer protection: it keeps the connection opaque
to a network observer, on top of (not instead of) the AES-GCM + RSA
signature protections applied to the message content itself.

Handshake initiation rule: to avoid both sides racing to start a handshake at
once, only the client whose username sorts lexicographically *lower* sends
the first handshake_init; the other client only responds when it receives
one. This is a local, deterministic tie-break -- it carries no security
weight, it just avoids a duplicate handshake.

Phase 5 adds RSA-2048 signatures for non-repudiation, on top of (not instead
of) the Phase 3 ECDH session key. The two serve different purposes: the
session key proves "encrypted for this pair of peers," while a signature
proves "this specific long-term identity wrote this specific message" --
something a third party could later be convinced of, which the symmetric
session key alone can never provide. On registration this client generates
its own RSA keypair (crypto_engine/signatures.py), keeps the private key
local (auth/keystore.py) and sends only the public key to the server. Before
sending, the plaintext is signed and the {message, signature} pair is what
gets AES-GCM encrypted -- so the signature is protected in transit too, not
sent in the clear. After decrypting an incoming message, the signature is
verified against the sender's public key (fetched once via "get_pubkey" and
cached for the session); a message that fails verification is warned about
and discarded, never displayed.

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
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.keystore import load_private_key, save_private_key  # noqa: E402
from crypto_engine.aes_gcm import DecryptionError, decrypt, encrypt  # noqa: E402
from crypto_engine.dh_exchange import compute_shared_key  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import deserialize_public_key  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import serialize_public_key, sign, verify  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CAFILE = os.path.join(_PROJECT_ROOT, "certs", "server.crt")


class TLSSetupError(Exception):
    """Raised when we can't build/complete a trusted TLS connection to the
    server -- missing CA file, handshake failure, or certificate the client
    doesn't recognize."""


def connect_tls(host, port, cafile=DEFAULT_CAFILE, server_hostname="localhost"):
    """Open a TCP connection to (host, port) and wrap it in TLS, verifying
    the server's certificate against our own self-signed CA.

    Deliberately does NOT set check_hostname=False or CERT_NONE as a
    shortcut -- that would accept literally any certificate from anyone,
    defeating the entire point of using TLS. Instead we trust exactly the
    one self-signed certificate this project generated (certs/server.crt),
    loaded as our trusted CA via load_verify_locations, which is the correct
    way to pin trust to a self-signed cert you control.
    """
    if not os.path.exists(cafile):
        raise TLSSetupError(
            f"TLS CA certificate not found at {cafile}.\n"
            f"Run `python certs/generate_certs.py` once (the server needs "
            f"the same cert) before connecting."
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=cafile)
    except ssl.SSLError as exc:
        raise TLSSetupError(f"Could not load CA certificate from {cafile}: {exc}") from exc

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_sock.connect((host, port))
    except OSError as exc:
        raw_sock.close()
        raise TLSSetupError(f"Could not connect to {host}:{port} -- {exc}") from exc

    try:
        tls_sock = context.wrap_socket(raw_sock, server_hostname=server_hostname)
    except ssl.SSLCertVerificationError as exc:
        raw_sock.close()
        raise TLSSetupError(
            f"Server certificate verification failed -- refusing to connect. "
            f"({exc})\nThis usually means the server is using a different "
            f"cert than the one in {cafile}; make sure both sides ran the "
            f"same certs/generate_certs.py output."
        ) from exc
    except ssl.SSLError as exc:
        raw_sock.close()
        raise TLSSetupError(f"TLS handshake failed: {exc}") from exc
    return tls_sock


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
        # Results of "pubkey_result" envelopes, similarly handed off.
        self.pubkey_results = queue.Queue()

        # Handshake / session state, guarded by _lock since the receiver
        # thread and the send loop both touch it.
        self._lock = threading.Lock()
        self._pending_private_key = None  # our transient ECDH private key
        self.session_key = None  # 32-byte AES key once handshake completes
        self._handshake_started = False
        self._outgoing_queue = []  # messages typed before the key was ready

        # Phase 5: this identity's long-term RSA signing key (loaded/generated
        # during authenticate()), and the peer's cached public key used to
        # verify their signatures. peer_public_key is fetched once via
        # get_pubkey before the chat loop starts (see fetch_peer_public_key);
        # it is never re-fetched lazily from inside receive_loop, since that
        # would deadlock the very queue it would be waiting on.
        self.rsa_private_key = None
        self.peer_public_key = None

    def send_envelope(self, envelope):
        try:
            self.sock.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
        except OSError:
            self.stop_event.set()

    # --- authentication --------------------------------------------------

    def register(self, username, password, public_key_pem=None):
        envelope = {"type": "register", "username": username, "password": password}
        if public_key_pem:
            envelope["public_key"] = public_key_pem
        self.send_envelope(envelope)

    def login(self, username, password):
        self.send_envelope({"type": "login", "username": username, "password": password})

    def fetch_peer_public_key(self, timeout=10):
        """Request the peer's RSA public key from the server and cache it.

        Must be called from the main thread (not from within receive_loop):
        it blocks on pubkey_results, which is only filled by the receiver
        thread reading further lines -- calling this from inside that same
        thread would deadlock.
        """
        self.send_envelope({"type": "get_pubkey", "username": self.peer})
        try:
            result = self.pubkey_results.get(timeout=timeout)
        except queue.Empty:
            return False
        if result is None or not result.get("success") or not result.get("public_key"):
            return False
        try:
            self.peer_public_key = deserialize_public_key(
                result["public_key"].encode("utf-8")
            )
        except ValueError:
            return False
        return True

    # --- handshake -----------------------------------------------------

    def initiate_handshake(self):
        with self._lock:
            if self._handshake_started or self.session_key is not None:
                return
            self._handshake_started = True
            private_key, public_bytes = generate_ecdh_keypair()
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
        private_key, public_bytes = generate_ecdh_keypair()
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

        # Sign THEN encrypt: the plaintext is signed with our own long-term
        # RSA private key first, and the {message, signature} pair is what
        # actually gets AES-GCM encrypted -- so the signature is protected
        # in transit just like the message text, never sent in the clear.
        message_bytes = text.encode("utf-8")
        if self.rsa_private_key is not None:
            signature = sign(self.rsa_private_key, message_bytes)
        else:
            # No local signing key (e.g. this client never registered/loaded
            # one) -- send unsigned rather than crash. The receiver will
            # reject an empty signature against a real public key, so this
            # only matters for a misconfigured/legacy account.
            signature = b""
        inner_payload = json.dumps({
            "message": text,
            "signature": b64(signature),
        }).encode("utf-8")

        box = encrypt(key, inner_payload)
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
        sender = envelope.get("from", self.peer)
        if key is None:
            print(f"\r[!] Received an encrypted message from {sender} "
                  f"before a session key was established -- dropped.\n> ", end="", flush=True)
            return

        # Decrypt first (unchanged Phase 3 flow) ...
        try:
            plaintext = decrypt(
                key,
                unb64(envelope["nonce"]),
                unb64(envelope["ciphertext"]),
                unb64(envelope["tag"]),
            )
        except (DecryptionError, KeyError, ValueError):
            print(f"\r[!] WARNING: message from {sender} failed "
                  f"authentication (tampered or wrong key) -- discarded.\n> ",
                  end="", flush=True)
            return

        # ... then extract {message, signature} and verify the signature
        # against the sender's cached RSA public key. A message that fails
        # verification -- tampered, forged, or from an unverifiable identity
        # -- is warned about and discarded, never displayed.
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            message_text = inner["message"]
            signature = unb64(inner["signature"])
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            print(f"\r[!] WARNING: message from {sender} was malformed after "
                  f"decryption -- discarded.\n> ", end="", flush=True)
            return

        if self.peer_public_key is None:
            print(f"\r[!] WARNING: cannot verify signature from {sender} -- "
                  f"their public key is unknown -- discarded.\n> ", end="", flush=True)
            return

        if not verify(self.peer_public_key, message_text.encode("utf-8"), signature):
            print(f"\r[!] WARNING: signature verification FAILED for message "
                  f"from {sender} -- possible tampering or forgery -- "
                  f"discarded.\n> ", end="", flush=True)
            return

        print(f"\r{sender}: {message_text}\n> ", end="", flush=True)

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
                    elif etype == "pubkey_result":
                        self.pubkey_results.put(envelope)
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
            # Unblock anyone still waiting on an auth or pubkey result.
            self.auth_results.put(None)
            self.pubkey_results.put(None)


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
            # Fresh long-term RSA identity for this account: generate it,
            # keep the private key local (never sent anywhere), and submit
            # only the public key alongside the registration envelope.
            rsa_private_key, rsa_public_key = generate_rsa_keypair()
            public_key_pem = serialize_public_key(rsa_public_key).decode("ascii")
            client.register(username, password, public_key_pem=public_key_pem)
        else:
            client.login(username, password)

        result = client.auth_results.get()
        if result is None:
            print("[!] Connection lost during authentication.")
            return False
        if result.get("success"):
            print(f"[*] {result.get('reason', 'Success.')}")
            if choice in ("1", "register"):
                save_private_key(username, rsa_private_key)
                client.rsa_private_key = rsa_private_key
            else:
                client.rsa_private_key = load_private_key(username)
                if client.rsa_private_key is None:
                    print(f"[!] No local signing key found for '{username}' on this "
                          f"machine -- outgoing messages will be sent unsigned, and "
                          f"the recipient's client will reject them. Register from "
                          f"this machine, or copy your private key here, to fix this.")
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
    parser.add_argument("--cafile", default=DEFAULT_CAFILE,
                         help="CA certificate to verify the server against "
                              "(default: certs/server.crt)")
    args = parser.parse_args()

    peer = args.peer or input("Peer username to chat securely with: ").strip()
    if not peer:
        print("A peer username is required.")
        sys.exit(1)

    try:
        sock = connect_tls(args.host, args.port, cafile=args.cafile)
    except TLSSetupError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    client = SecureChatClient(sock, username=None, peer=peer)
    threading.Thread(target=client.receive_loop, daemon=True).start()

    if args.username and args.password:
        # Non-interactive path, for scripted demos/tests only.
        client.username = args.username
        rsa_private_key = None
        if args.register:
            rsa_private_key, rsa_public_key = generate_rsa_keypair()
            public_key_pem = serialize_public_key(rsa_public_key).decode("ascii")
            client.register(args.username, args.password, public_key_pem=public_key_pem)
        else:
            client.login(args.username, args.password)
        result = client.auth_results.get()
        authenticated = bool(result and result.get("success"))
        if result:
            print(f"[{'*' if authenticated else '!'}] {result.get('reason')}")
        if authenticated:
            if args.register:
                save_private_key(args.username, rsa_private_key)
                client.rsa_private_key = rsa_private_key
            else:
                client.rsa_private_key = load_private_key(args.username)
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

    # Fetch the peer's public key once, up front, so incoming signed
    # messages can be verified as soon as they arrive. If the peer hasn't
    # registered yet (or has no key on file), chat still proceeds, but every
    # incoming message will be rejected as unverifiable until reconnecting
    # after the peer has registered.
    if not client.fetch_peer_public_key():
        print(f"[!] Could not fetch {peer}'s public key (they may not be "
              f"registered yet) -- their messages cannot be verified and "
              f"will be rejected until you reconnect.")

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
