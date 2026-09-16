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

Phase 7a signs the ECDH handshake itself: Phase 3's handshake_init/
handshake_response envelopes carried a raw, *unsigned* ECDH public key. A
malicious or compromised relay server -- note this is a different threat
than a network eavesdropper, and TLS (Phase 6) does not defend against it,
since the server is the trusted TLS endpoint -- could substitute its own
ECDH public key for either peer's, completing two separate handshakes
(attacker<->A, attacker<->B) while both clients believe they're talking
directly to each other. Since each client already has a long-term RSA
identity (Phase 5), the fix is to sign the ECDH public key bytes with the
sender's RSA private key before sending, and have the receiver verify that
signature against the sender's already-fetched RSA public key *before*
computing the shared secret -- a failed verification aborts the handshake
entirely, deriving no session key. After a successful handshake, both sides
also print a short human-readable fingerprint of the peer's RSA public key,
so two people can read it aloud to each other (voice call, in person) and
catch a MITM even if every automated check were somehow fooled -- the
"check key fingerprints" mitigation.

Phase 7b adds replay protection to chat messages: previously a captured,
valid (ciphertext, tag, signature) could be resent verbatim later and would
still pass AES-GCM and signature verification, since neither checks
freshness. A Unix timestamp is now included in what gets signed (so it can't
be altered without detection) and checked on receipt against a freshness
window; the AES-GCM nonce (already unique per message by construction) is
additionally tracked per-sender in memory for the same window, rejecting an
exact repeat even if it somehow fell within the timestamp bounds.

Wire format: one JSON object per line, matching server/server.py. Binary
fields (public keys, nonce, ciphertext, tag, signatures) are base64-encoded
for JSON.

Stage 8 (GUI): SecureChatClient's logic methods (register/login, handshake,
send/receive) were always separate from the terminal-specific presentation
code (authenticate()/main(), which use input()/print()) -- the GUI reuses
SecureChatClient directly rather than those two functions. What SecureChatClient
itself mixed in was print() calls *inside* its own logic methods (handshake
progress, warnings, incoming messages). Rather than rip those out (risking
subtly changing the terminal client's behavior) an optional structured
`event_callback` was added: every one of those print() sites also emits a
(kind, data) event through it if one was supplied. The terminal client
doesn't pass one, so it behaves byte-for-byte as before; gui/chat_gui.py
passes one to drive its own display instead of scraping stdout.
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
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.keystore import load_private_key, save_private_key  # noqa: E402
from crypto_engine.aes_gcm import DecryptionError, decrypt, encrypt  # noqa: E402
from crypto_engine.dh_exchange import compute_shared_key  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import deserialize_public_key, fingerprint  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import serialize_public_key, sign, verify  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

# Phase 7b replay-protection tuning. A message older than REPLAY_WINDOW_SECONDS
# is rejected as stale/possibly replayed; one more than CLOCK_SKEW_SECONDS in
# the future is rejected too (allows for small, honest clock differences
# between machines without opening a large future-dated replay window).
REPLAY_WINDOW_SECONDS = 30
CLOCK_SKEW_SECONDS = 5
# How long a (sender, nonce) pair is remembered for exact-repeat detection --
# a little longer than the freshness window is enough, since anything older
# than REPLAY_WINDOW_SECONDS is already rejected by the timestamp check alone.
_NONCE_MEMORY_SECONDS = REPLAY_WINDOW_SECONDS + CLOCK_SKEW_SECONDS


def chat_signable_bytes(message: str, timestamp: int) -> bytes:
    """Canonical bytes signed for a chat message: the message text and its
    timestamp together, so the timestamp can't be stripped or altered by a
    relay/attacker without invalidating the signature. Both the sender
    (signing) and receiver (verifying) must build this identically."""
    return json.dumps(
        {"message": message, "timestamp": timestamp}, sort_keys=True
    ).encode("utf-8")


def is_timestamp_fresh(timestamp, now=None,
                        window=REPLAY_WINDOW_SECONDS, skew=CLOCK_SKEW_SECONDS):
    """True if `timestamp` (Unix epoch seconds) is neither older than
    `window` seconds nor more than `skew` seconds in the future, relative to
    `now` (defaults to the current time)."""
    if now is None:
        now = time.time()
    try:
        timestamp = float(timestamp)
    except (TypeError, ValueError):
        return False
    return (now - window) <= timestamp <= (now + skew)

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
    def __init__(self, sock, username, peer, event_callback=None):
        self.sock = sock
        self.username = username
        self.peer = peer
        self.stop_event = threading.Event()

        # Optional structured hook for a non-terminal presentation layer
        # (see gui/chat_gui.py): called as event_callback(kind: str, data:
        # dict) alongside every existing print() in this class, wrapped
        # defensively so a bug in a GUI handler can never break the
        # underlying protocol/crypto logic. None (the default) makes this a
        # complete no-op -- the terminal client's behavior is unchanged.
        self.on_event = event_callback

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
        # verify their signatures. main() fetches this once, synchronously,
        # right after authentication succeeds -- but a Phase 7a signed
        # handshake can legitimately start *before* that finishes (e.g. the
        # peer was already online and roster/user_joined fires the moment
        # receive_loop starts, well before the main thread gets around to
        # its own explicit fetch). Rather than race that and fail spuriously,
        # _handle_handshake_init/_response DEFER (not abort) when
        # peer_public_key isn't cached yet: see _defer_or_request_pubkey and
        # _replay_deferred_handshake below. A handshake only ever ABORTS when
        # a signature was actually checked and failed -- never merely because
        # the key hadn't arrived yet.
        self.rsa_private_key = None
        self.peer_public_key = None
        self.peer_public_key_pem = None  # raw PEM string, for fingerprinting

        # Phase 7a race-avoidance: envelopes that arrived before we had the
        # peer's public key cached, held here until it arrives (or we learn
        # it never will), plus whether *we* should initiate once it's ready.
        self._pubkey_requested = False
        self._deferred_handshake_envelopes = []  # list of ("init"|"response", envelope)
        self._initiate_when_key_ready = False

        # Phase 7b replay protection: (sender, nonce_b64) -> time.time() when
        # first seen, for exact-repeat detection within _NONCE_MEMORY_SECONDS.
        # Guarded by _lock along with everything else above.
        self._seen_nonces = {}

    def _emit(self, kind, **data):
        """Notify the presentation layer of a structured event, if one is
        listening. Never allowed to raise into the caller -- a broken GUI
        handler must not be able to break the underlying protocol logic."""
        if self.on_event is None:
            return
        try:
            self.on_event(kind, data)
        except Exception:
            pass

    def send_envelope(self, envelope):
        try:
            self.sock.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
        except OSError:
            self.stop_event.set()
            return
        # Wire-log hook: every envelope this client puts on the wire, raw --
        # this is what a "what's actually crossing the network" panel shows.
        self._emit("envelope_sent", envelope=envelope)

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

        BLOCKING -- must be called from the main thread (not from within
        receive_loop): it waits on pubkey_results, which is only filled by
        the receiver thread reading further lines, so calling this from
        inside that same thread would deadlock. main() uses this once, right
        after authentication, as the common-case fetch. For the race where a
        handshake message arrives before this has completed, see
        _defer_or_request_pubkey (non-blocking, safe to call from
        receive_loop) instead.
        """
        self.send_envelope({"type": "get_pubkey", "username": self.peer})
        try:
            result = self.pubkey_results.get(timeout=timeout)
        except queue.Empty:
            return False
        return self._cache_peer_public_key(result)

    def _cache_peer_public_key(self, result):
        """Store a pubkey_result envelope's key into peer_public_key(_pem) if
        it's valid and for our peer. Returns True on success. Shared by the
        blocking fetch_peer_public_key() and the non-blocking receive_loop path."""
        if (
            not result
            or result.get("username") != self.peer
            or not result.get("success")
            or not result.get("public_key")
        ):
            return False
        try:
            self.peer_public_key = deserialize_public_key(result["public_key"].encode("utf-8"))
        except ValueError:
            return False
        # Cache the exact PEM text too (not just the parsed key object) so
        # the fingerprint we print matches byte-for-byte what the peer would
        # compute over their own public key PEM.
        self.peer_public_key_pem = result["public_key"]
        return True

    def _defer_or_request_pubkey(self, kind, envelope):
        """Called from receive_loop when a handshake_init/handshake_response
        arrives but we don't have the peer's public key cached yet. Holds
        the envelope to replay once the key arrives (see
        _replay_deferred_handshake), and -- non-blocking, so safe here --
        (re)sends a get_pubkey request if we haven't already got one in
        flight. This is a defer, not a failure: the handshake still has not
        been verified, so no session key exists yet, but we haven't given up
        on it either."""
        with self._lock:
            self._deferred_handshake_envelopes.append((kind, envelope))
            already_requested = self._pubkey_requested
            self._pubkey_requested = True
        if not already_requested:
            self.send_envelope({"type": "get_pubkey", "username": self.peer})
        print(f"\r[*] Waiting on {self.peer}'s public key to verify an incoming "
              f"handshake message...\n> ", end="", flush=True)
        self._emit("handshake_waiting", peer=self.peer)

    def _replay_deferred_handshake(self):
        """Called from receive_loop right after peer_public_key is (or
        definitively cannot be) cached: replays any handshake_init/response
        that arrived too early, and starts our own handshake if we were
        waiting to be the initiator."""
        with self._lock:
            deferred = self._deferred_handshake_envelopes
            self._deferred_handshake_envelopes = []
            want_initiate = self._initiate_when_key_ready
            self._initiate_when_key_ready = False

        if self.peer_public_key is None:
            if deferred or want_initiate:
                self._abort_handshake(
                    f"{self.peer}'s public key could not be retrieved from the "
                    f"server -- they may not be registered."
                )
            return

        for kind, envelope in deferred:
            if kind == "init":
                self._handle_handshake_init(envelope)
            elif kind == "response":
                self._handle_handshake_response(envelope)
        if want_initiate and self.session_key is None:
            self.initiate_handshake()

    # --- handshake -----------------------------------------------------

    def _sign_ecdh_pubkey(self, ecdh_public_bytes):
        """Sign our own ECDH public key bytes with our RSA private key, for
        the peer to verify before trusting this handshake message (Phase 7a).
        Returns b"" (an empty signature, which verify() always rejects) if we
        have no local signing key -- sent rather than crashing, matching the
        same fallback used for chat messages."""
        if self.rsa_private_key is None:
            return b""
        return sign(self.rsa_private_key, ecdh_public_bytes)

    def _initiate_handshake_when_ready(self):
        """Called from receive_loop when roster/user_joined says our peer is
        online and we're the designated initiator. If we already have their
        public key cached, start the handshake immediately (the common
        case); otherwise request it (non-blocking) and let
        _replay_deferred_handshake start the handshake once it arrives --
        this is what avoids the race of initiating before we could even
        verify a *reply* to our own handshake_init."""
        with self._lock:
            if self._handshake_started or self.session_key is not None:
                return
            have_key = self.peer_public_key is not None
            if not have_key:
                self._initiate_when_key_ready = True
                already_requested = self._pubkey_requested
                self._pubkey_requested = True
        if have_key:
            self.initiate_handshake()
        elif not already_requested:
            self.send_envelope({"type": "get_pubkey", "username": self.peer})

    def initiate_handshake(self):
        with self._lock:
            if self._handshake_started or self.session_key is not None:
                return
            self._handshake_started = True
            private_key, public_bytes = generate_ecdh_keypair()
            self._pending_private_key = private_key

        print(f"\r[*] Starting key exchange with {self.peer}...\n> ", end="", flush=True)
        self._emit("handshake_started", peer=self.peer)
        self.send_envelope({
            "type": "handshake_init",
            "from": self.username,
            "to": self.peer,
            "pubkey": b64(public_bytes),
            # Phase 7a: sign our ECDH public key with our RSA identity key so
            # the peer can confirm it really came from us, not a relay/MITM
            # substituting its own key.
            "handshake_sig": b64(self._sign_ecdh_pubkey(public_bytes)),
        })

    def _abort_handshake(self, reason):
        with self._lock:
            self._handshake_started = False
            self._pending_private_key = None
        print(f"\r[!] HANDSHAKE ABORTED with {self.peer}: {reason} No session key "
              f"was derived -- this connection is NOT secure. Possible MITM; do not "
              f"trust any messages claiming to be from {self.peer} right now.\n> ",
              end="", flush=True)
        self._emit("handshake_aborted", peer=self.peer, reason=reason)

    def _handle_handshake_init(self, envelope):
        if self.peer_public_key is None:
            # Not a failure yet -- we just don't have the verification key
            # in hand this instant. Defer and ask for it; see
            # _defer_or_request_pubkey / _replay_deferred_handshake. We still
            # derive no session key until a signature actually verifies.
            self._defer_or_request_pubkey("init", envelope)
            return

        peer_pub = unb64(envelope["pubkey"])
        handshake_sig = unb64(envelope.get("handshake_sig", ""))
        if not verify(self.peer_public_key, peer_pub, handshake_sig):
            self._abort_handshake(
                f"the ECDH public key claimed to be from {self.peer} did NOT "
                f"verify against their RSA public key -- it may have been "
                f"substituted by the relay server or an attacker."
            )
            return

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
            "handshake_sig": b64(self._sign_ecdh_pubkey(public_bytes)),
        })
        self._finish_handshake(session_key)

    def _handle_handshake_response(self, envelope):
        with self._lock:
            have_pending = self._pending_private_key is not None
        if not have_pending:
            return  # response we didn't ask for; ignore

        if self.peer_public_key is None:
            # Leave _pending_private_key in place -- we'll re-enter this
            # same method (with the same envelope) via
            # _replay_deferred_handshake once the key arrives.
            self._defer_or_request_pubkey("response", envelope)
            return

        with self._lock:
            private_key = self._pending_private_key
            self._pending_private_key = None
        if private_key is None:
            return  # consumed by a concurrent call already; nothing to do

        peer_pub = unb64(envelope["pubkey"])
        handshake_sig = unb64(envelope.get("handshake_sig", ""))
        if not verify(self.peer_public_key, peer_pub, handshake_sig):
            self._abort_handshake(
                f"the ECDH public key claimed to be from {self.peer} did NOT "
                f"verify against their RSA public key -- it may have been "
                f"substituted by the relay server or an attacker."
            )
            del private_key
            return

        session_key = compute_shared_key(private_key, peer_pub)
        del private_key
        self._finish_handshake(session_key)

    def _finish_handshake(self, session_key):
        with self._lock:
            self.session_key = session_key
            queued = self._outgoing_queue
            self._outgoing_queue = []
        print(f"\r[*] Secure session established with {self.peer} "
              f"(AES-256-GCM key derived via ECDH, authenticated by RSA signature).",
              end="", flush=True)
        self._emit("handshake_established", peer=self.peer)
        # Phase 7a "check key fingerprints" mitigation: print a short,
        # human-readable fingerprint of the peer's RSA public key. Two people
        # can read this aloud to each other (voice call, in person) to
        # independently confirm they hold the same identity for their peer,
        # catching a MITM even if every automated check were somehow fooled.
        if self.peer_public_key_pem:
            fp = fingerprint(self.peer_public_key_pem)
            print(f"\n[*] {self.peer}'s key fingerprint: {fp}\n"
                  f"    Verify this out-of-band (voice/in person) with {self.peer} "
                  f"to rule out a man-in-the-middle.\n> ", end="", flush=True)
            self._emit("peer_fingerprint", peer=self.peer, fingerprint=fp)
        else:
            print("\n> ", end="", flush=True)
        for text in queued:
            self._encrypt_and_send(text)

    # --- chat ------------------------------------------------------------

    def _encrypt_and_send(self, text):
        with self._lock:
            key = self.session_key

        # Sign THEN encrypt: the plaintext (Phase 7b: plus a timestamp) is
        # signed with our own long-term RSA private key first, and the
        # {message, timestamp, signature} triple is what actually gets
        # AES-GCM encrypted -- so both the message and its timestamp travel
        # protected inside the same ciphertext, never sent in the clear, and
        # the timestamp can't be stripped or altered without invalidating
        # the signature.
        timestamp = int(time.time())
        signable = chat_signable_bytes(text, timestamp)
        if self.rsa_private_key is not None:
            signature = sign(self.rsa_private_key, signable)
        else:
            # No local signing key (e.g. this client never registered/loaded
            # one) -- send unsigned rather than crash. The receiver will
            # reject an empty signature against a real public key, so this
            # only matters for a misconfigured/legacy account.
            signature = b""
        inner_payload = json.dumps({
            "message": text,
            "timestamp": timestamp,
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
        # The terminal client doesn't need an echo of what the user just
        # typed (it's already visible in their own terminal); a GUI's chat
        # panel does, since there's no other record of "what I sent".
        self._emit("message_sent", peer=self.peer, message=text, timestamp=timestamp)

    def send_message(self, text):
        with self._lock:
            ready = self.session_key is not None
            if not ready:
                self._outgoing_queue.append(text)
        if not ready:
            self.initiate_handshake()
            print("[*] Message queued until the secure session is ready.")
            self._emit("message_queued", peer=self.peer, message=text)
            return
        self._encrypt_and_send(text)

    def _handle_chat(self, envelope):
        with self._lock:
            key = self.session_key
        sender = envelope.get("from", self.peer)
        if key is None:
            print(f"\r[!] Received an encrypted message from {sender} "
                  f"before a session key was established -- dropped.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="no_session_key",
                       detail="received before a session key was established")
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
            self._emit("message_rejected", sender=sender, reason="decryption_failed",
                       detail="AES-GCM authentication failed (tampered or wrong key)")
            return

        # ... then extract {message, timestamp, signature} and verify the
        # signature (now covering the timestamp too, Phase 7b) against the
        # sender's cached RSA public key. A message that fails verification
        # -- tampered, forged, or from an unverifiable identity -- is warned
        # about and discarded, never displayed.
        try:
            inner = json.loads(plaintext.decode("utf-8"))
            message_text = inner["message"]
            timestamp = inner["timestamp"]
            signature = unb64(inner["signature"])
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            print(f"\r[!] WARNING: message from {sender} was malformed after "
                  f"decryption -- discarded.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="malformed",
                       detail="payload was malformed after decryption")
            return

        if self.peer_public_key is None:
            print(f"\r[!] WARNING: cannot verify signature from {sender} -- "
                  f"their public key is unknown -- discarded.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="unknown_peer_key",
                       detail="sender's public key is unknown")
            return

        signable = chat_signable_bytes(message_text, timestamp)
        if not verify(self.peer_public_key, signable, signature):
            print(f"\r[!] WARNING: signature verification FAILED for message "
                  f"from {sender} -- possible tampering or forgery -- "
                  f"discarded.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="signature_failed",
                       detail="RSA signature verification failed (tampering or forgery)")
            return

        # Phase 7b, check 1: freshness window. A captured, validly-signed,
        # validly-encrypted message resent later (or a legitimate message
        # that's simply too old) is rejected here -- the signature alone
        # can't catch this, since it says nothing about *when* the message
        # is being presented, only that its content+timestamp are authentic.
        if not is_timestamp_fresh(timestamp):
            print(f"\r[!] WARNING: message from {sender} has a stale or "
                  f"future timestamp ({timestamp}) -- rejected as too old / "
                  f"a possible replay -- discarded.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="stale_timestamp",
                       detail=f"timestamp {timestamp} outside the freshness window")
            return

        # Phase 7b, check 2: exact-repeat detection (belt-and-suspenders).
        # Even a message that somehow lands inside the freshness window is
        # rejected if we've already seen this exact (sender, nonce) pair --
        # AES-GCM nonces are fresh random values per encrypt() call, so a
        # genuine resend from the sender would carry a *new* nonce; seeing
        # the same nonce twice means the same envelope was replayed verbatim.
        nonce_b64 = envelope.get("nonce", "")
        now = time.time()
        with self._lock:
            # Prune anything old enough that it could no longer pass the
            # freshness check anyway, to bound memory over a long session.
            stale_keys = [
                k for k, seen_at in self._seen_nonces.items()
                if now - seen_at > _NONCE_MEMORY_SECONDS
            ]
            for k in stale_keys:
                del self._seen_nonces[k]

            dedup_key = (sender, nonce_b64)
            if dedup_key in self._seen_nonces:
                already_seen = True
            else:
                already_seen = False
                self._seen_nonces[dedup_key] = now

        if already_seen:
            print(f"\r[!] WARNING: duplicate message detected from {sender} "
                  f"(same nonce seen before) -- rejected as a replay -- "
                  f"discarded.\n> ", end="", flush=True)
            self._emit("message_rejected", sender=sender, reason="replay_duplicate",
                       detail="exact same (sender, nonce) already seen -- replay")
            return

        print(f"\r{sender}: {message_text}\n> ", end="", flush=True)
        self._emit("message_received", sender=sender, message=message_text, timestamp=timestamp)

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

                    # Wire-log hook: every envelope this client reads off
                    # the wire, raw, before any of it is interpreted below.
                    self._emit("envelope_received", envelope=envelope)

                    etype = envelope.get("type")
                    if etype in ("register_result", "login_result"):
                        self.auth_results.put(envelope)
                    elif etype == "pubkey_result":
                        # Always route to anyone blocked in fetch_peer_public_key()...
                        self.pubkey_results.put(envelope)
                        # ...and also opportunistically cache + replay any
                        # handshake messages that arrived before we had this
                        # key (non-blocking -- safe to do from this thread).
                        if envelope.get("username") == self.peer:
                            self._cache_peer_public_key(envelope)
                            self._replay_deferred_handshake()
                    elif etype == "system":
                        print(f"\r{envelope.get('text', '')}\n> ", end="", flush=True)
                        self._emit("system_message", text=envelope.get("text", ""))
                    elif etype == "roster":
                        if self.peer in envelope.get("users", []) and self.username < self.peer:
                            self._initiate_handshake_when_ready()
                    elif etype == "user_joined":
                        if envelope.get("username") == self.peer and self.username < self.peer:
                            self._initiate_handshake_when_ready()
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
                self._emit("disconnected", reason="connection lost")
            self.stop_event.set()
            # Unblock anyone still waiting on an auth or pubkey result.
            self.auth_results.put(None)
            self.pubkey_results.put(None)


def print_own_fingerprint(rsa_private_key):
    """Print this identity's own RSA key fingerprint, the same way the
    peer's is printed after a handshake -- so a user can read theirs aloud
    when the other person asks "what's your fingerprint?"."""
    if rsa_private_key is None:
        return
    own_pem = serialize_public_key(rsa_private_key.public_key())
    print(f"[*] Your key fingerprint: {fingerprint(own_pem)}")


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
            print_own_fingerprint(client.rsa_private_key)
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
            print_own_fingerprint(client.rsa_private_key)
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
