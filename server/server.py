"""Relay server: threaded TCP, JSON-line envelope protocol.

Phase 1 broadcast raw plaintext lines to everyone. Phase 3 replaced that with
a small JSON envelope protocol (see README.md "How the handshake works") so
the server can route ECDH handshake messages and encrypted chat messages to a
*specific* named peer instead of broadcasting them to the whole room. Phase 4
adds a "register"/"login" step in front of that: a client must authenticate
with a username + password (checked against server/user_store.py, which
stores only a PBKDF2 hash -- see auth/password_hash.py) before it is admitted
to the roster or allowed to send anything else.

Crucially, the server is a dumb relay for these envelope types:
  - "handshake_init" / "handshake_response": carry only public key bytes
    (base64-encoded). Public keys are, by design, safe for the server to see.
  - "chat": carries only nonce/ciphertext/tag (base64-encoded AES-GCM output).
    The server never sees plaintext, never sees a private key, and never sees
    (or computes) the derived shared session key -- it just forwards opaque
    bytes from sender to the named recipient.

Phase 5 adds long-term RSA identities for message signing (non-repudiation --
see crypto_engine/signatures.py and client.py). Each user's RSA *public* key
is submitted at registration and stored in server/user_store.py alongside
their password hash; the matching private key never leaves the client. A
"get_pubkey" envelope lets one client fetch another's public key by username
so it can verify that user's signatures -- the server just looks up and
returns what was already public by design.

Phase 6 closes the register/login plaintext-on-the-wire gap called out above:
every accepted connection is now wrapped in TLS (ssl.PROTOCOL_TLS_SERVER)
*before* a single byte of the envelope protocol is read, so even the very
first "register"/"login" envelope travels inside the TLS tunnel. This is a
transport-layer protection, layered on top of (not instead of) the
application-layer crypto from Phases 2/3/5: TLS keeps the connection itself
opaque to a network observer (nobody outside can even see "type": "login" or
the JSON structure), while AES-GCM + the RSA signatures still protect chat
content and identity even in a scenario where the relay server itself is
compromised (TLS only protects data in transit to/from the server, not what
the server does with it once decrypted at that endpoint). Certs are
generated locally by each teammate via certs/generate_certs.py -- see
README.md -- and are never committed (a shared private key would let anyone
with repo access impersonate the server).

Wire format: one UTF-8 JSON object per line (newline-terminated), now
carried inside the TLS tunnel. Every envelope has a "type" field. Envelopes
that name a "to" recipient are unicast to that user if online; everything
else (register, login, roster) is handled directly by the server.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from user_store import get_public_key, register_user, verify_user
except ImportError:  # running as part of the `server` package (e.g. tests)
    from server.user_store import get_public_key, register_user, verify_user

from certs.generate_certs import cert_fingerprint_from_file  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import sign  # noqa: E402
# Same dual-mode import as user_store above: run as a script
# (`python server/server.py`, the documented way) the server/ directory is on
# sys.path and `import server` would find THIS FILE rather than the package,
# so the sibling modules must be imported top-level there; imported as part
# of the `server` package (tests, demos) they come from the package.
try:
    from lockout import LockoutGuard
    from security_log import log_event
except ImportError:
    from server.lockout import LockoutGuard  # noqa: E402
    from server.security_log import log_event  # noqa: E402
from transport import LockedTLSSocket  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CERT_PATH = os.path.join(_PROJECT_ROOT, "certs", "server.crt")
DEFAULT_KEY_PATH = os.path.join(_PROJECT_ROOT, "certs", "server.key")


class CertsMissingError(Exception):
    """Raised when certs/server.crt or certs/server.key can't be found."""


def build_server_ssl_context(certfile=DEFAULT_CERT_PATH, keyfile=DEFAULT_KEY_PATH):
    """Build the server-side TLS context, loaded with our self-signed cert.

    Raises CertsMissingError with a clear, actionable message rather than
    letting a raw FileNotFoundError/SSLError surface if the certs haven't
    been generated yet.
    """
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        raise CertsMissingError(
            f"TLS certificate/key not found at {certfile} / {keyfile}.\n"
            f"Run `python certs/generate_certs.py` once to generate them "
            f"before starting the server."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except ssl.SSLError as exc:
        raise CertsMissingError(
            f"Failed to load TLS certificate/key from {certfile} / {keyfile}: {exc}\n"
            f"Try regenerating them with `python certs/generate_certs.py --force`."
        ) from exc
    return context

# Envelope types relayed verbatim to a specific "to" recipient without the
# server inspecting their payload beyond routing fields.
_RELAYED_TYPES = {"handshake_init", "handshake_response", "chat"}


# Stage C: Attack Lab. One-shot, opt-in attacks performed BY THE RELAY --
# the threat model this whole project defends against -- so the professor
# can watch a real attack happen and get caught live, in the same two chat
# windows, instead of only through a separate script. Every safety
# restriction below is enforced server-side, never trusted to the GUI:
#   * the server must be started with --lab (default: disabled, and in that
#     default state the server behaves exactly as it always has)
#   * even in --lab mode, a lab_control envelope is honored only from a
#     connection whose PEER ADDRESS is 127.0.0.1, so it can never be
#     triggered over a real network
#   * only from a connection that has already completed register/login
#     (the lab_control case in handle_client's main loop runs only after
#     _authenticate() has returned a name -- the same gate every chat/
#     handshake envelope is already behind)
# A rejected attempt (wrong mode, wrong address, or unknown action) is
# always logged as "lab_control_rejected" -- including when --lab was never
# passed at all -- so a real attacker probing for this feature leaves a
# trace. A performed attack is logged as "lab_attack_performed" and reported
# ONLY to the client that armed it, as "armed" / "performed" -- never as a
# claim that the attack succeeded. Whether it was actually caught is left
# entirely to the real, unmodified client-side checks (AES-GCM tag, RSA
# signature, replay window/nonce, hash chain, handshake signature) on
# whichever client receives the attacked envelope -- the server never
# announces a detection result, because in the real world a malicious relay
# obviously wouldn't either.
_LAB_ACTIONS = {"tamper_next", "replay_last", "drop_next", "mitm_next_handshake"}


class ChatServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 certfile=DEFAULT_CERT_PATH, keyfile=DEFAULT_KEY_PATH,
                 lab_mode=False, lockout=None):
        self.host = host
        self.port = port
        self.lab_mode = lab_mode
        # Stage D: login lockout + per-address rate limiting (server/lockout.py).
        # `lockout` is injectable so tests can use tiny thresholds/windows
        # instead of the real 5-failures/5-minute defaults.
        self.lockout = lockout if lockout is not None else LockoutGuard()
        # Built eagerly (not lazily in serve_forever) so a missing-certs
        # error surfaces immediately when the server is constructed, not
        # buried inside the accept loop.
        self.ssl_context = build_server_ssl_context(certfile, keyfile)
        # Fingerprint the cert we actually just loaded into memory -- printed
        # at startup (see serve_forever) so a stale server (still holding an
        # old cert after certs/server.crt was regenerated on disk without
        # restarting it) is diagnosable by comparing fingerprints, instead of
        # a bare CERTIFICATE_VERIFY_FAILED that gives no hint why.
        self.cert_fingerprint = cert_fingerprint_from_file(certfile)
        # username -> conn (the TLS-wrapped socket). Guarded by _lock: every
        # client thread mutates it on join/leave and reads it on every
        # route/broadcast.
        self.clients = {}
        self._lock = threading.Lock()

        # Listening socket + lifecycle (see listen()/shutdown()). `_open_conns`
        # tracks EVERY accepted TLS connection (not just authenticated ones in
        # self.clients) so shutdown() can force them all closed.
        self._srv = None
        self._stop = threading.Event()
        self._open_conns = set()

        # Stage C lab state, all guarded by _lab_lock (separate from _lock,
        # which is purely about self.clients, to avoid widening that lock's
        # critical sections). _lab_pending maps a TARGET username (whose
        # next matching outgoing envelope gets acted on) -> (action, armer
        # username). _last_chat_envelope maps a sender username -> the most
        # recent chat envelope genuinely relayed from them (used by
        # replay_last). _lab_attacker_key is a throwaway RSA identity
        # generated on first use for mitm_next_handshake -- signed with
        # this key, never with the real target's, so the victim's signature
        # check still fails exactly as it would for a real attacker.
        self._lab_lock = threading.Lock()
        self._lab_pending = {}
        self._last_chat_envelope = {}
        self._lab_attacker_key = None

    def _send(self, conn, envelope):
        try:
            conn.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
        except OSError:
            pass  # peer vanished; its own thread will clean it up

    def _send_system(self, conn, text):
        self._send(conn, {"type": "system", "text": text})

    def broadcast_system(self, text, exclude=None):
        with self._lock:
            targets = [c for c in self.clients.values() if c is not exclude]
        for conn in targets:
            self._send_system(conn, text)

    def broadcast_event(self, envelope, exclude=None):
        """Broadcast a structured (non-text) event, e.g. user_joined/user_left."""
        with self._lock:
            targets = [c for c in self.clients.values() if c is not exclude]
        for conn in targets:
            self._send(conn, envelope)

    def _notify_armer(self, armer_name, detail, **extra):
        with self._lock:
            armer_conn = self.clients.get(armer_name)
        if armer_conn is not None:
            self._send(armer_conn, dict({"type": "lab_attack_performed", "detail": detail},
                                        **extra))

    def _apply_lab_tamper_or_drop(self, envelope, sender_name):
        """Chat-envelope lab actions, applied (if armed) before the normal
        relay below. Returns the (possibly altered) envelope, or None if it
        should not be relayed at all (drop_next)."""
        with self._lab_lock:
            self._last_chat_envelope[sender_name] = envelope
            pending = self._lab_pending.get(sender_name)
            action = pending[0] if pending and pending[0] in ("tamper_next", "drop_next") else None
            if action:
                del self._lab_pending[sender_name]
                armer = pending[1]

        if action == "tamper_next":
            raw = bytearray(base64.b64decode(envelope["ciphertext"]))
            raw[0] ^= 0xFF  # flip every bit of the first ciphertext byte
            tampered = dict(envelope, ciphertext=base64.b64encode(bytes(raw)).decode("ascii"))
            detail = f"flipped a byte in {sender_name}'s next chat message's ciphertext"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=sender_name, armed_by=armer)
            self._notify_armer(armer, detail, action=action)
            return tampered
        if action == "drop_next":
            detail = f"silently dropped {sender_name}'s next chat message"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=sender_name, armed_by=armer)
            self._notify_armer(armer, detail, action=action)
            return None
        return envelope

    def _apply_lab_mitm(self, envelope, sender_name):
        """handshake_init lab action: substitute our own ECDH public key,
        signed with a throwaway attacker RSA key -- never the real sender's
        -- for the one being relayed. Returns the (possibly forged)
        envelope."""
        with self._lab_lock:
            pending = self._lab_pending.get(sender_name)
            if not pending or pending[0] != "mitm_next_handshake":
                return envelope
            del self._lab_pending[sender_name]
            armer = pending[1]
            if self._lab_attacker_key is None:
                self._lab_attacker_key = generate_rsa_keypair()[0]  # (private, public)
            attacker_key = self._lab_attacker_key

        _, attacker_ecdh_pub = generate_ecdh_keypair()
        attacker_sig = sign(attacker_key, attacker_ecdh_pub)
        forged = dict(envelope, pubkey=base64.b64encode(attacker_ecdh_pub).decode("ascii"),
                      handshake_sig=base64.b64encode(attacker_sig).decode("ascii"))
        detail = (f"substituted its own ECDH public key for {sender_name}'s in their next "
                 f"handshake, signed with an attacker key (not {sender_name}'s)")
        print(f"    [LAB] {detail}.")
        log_event("lab_attack_performed", action="mitm_next_handshake", target=sender_name,
                  armed_by=armer)
        self._notify_armer(armer, detail, action="mitm_next_handshake")
        return forged

    def route(self, envelope, sender_name):
        """Forward a handshake/chat envelope to its named recipient only."""
        etype = envelope.get("type")
        if etype == "chat":
            envelope = self._apply_lab_tamper_or_drop(envelope, sender_name)
            if envelope is None:
                return  # drop_next: never relayed
        elif etype == "handshake_init":
            envelope = self._apply_lab_mitm(envelope, sender_name)

        to_name = envelope.get("to")
        with self._lock:
            target = self.clients.get(to_name)
        if target is None:
            with self._lock:
                sender_conn = self.clients.get(sender_name)
            if sender_conn is not None:
                self._send_system(
                    sender_conn,
                    f"[!] {to_name} is not online -- message not delivered.",
                )
            return
        self._send(target, envelope)

    def _handle_lab_control(self, conn, addr, name, envelope):
        """Arm (or, for replay_last, immediately perform) a one-shot lab
        attack. See the _LAB_ACTIONS comment above ChatServer for the
        safety restrictions this enforces."""
        action = envelope.get("action")
        target = envelope.get("target") or name

        def reject(reason):
            log_event("lab_control_rejected", requested_by=name, from_addr=addr[0],
                      action=action, reason=reason)
            self._send(conn, {"type": "lab_control_result", "action": action,
                              "target": target, "armed": False, "detail": reason})

        if not self.lab_mode:
            reject("lab mode is not enabled on this server (start it with --lab)")
            return
        if addr[0] != "127.0.0.1":
            reject("lab_control is only accepted from a localhost connection")
            return
        if action not in _LAB_ACTIONS:
            reject(f"unknown lab action '{action}'")
            return

        if action == "replay_last":
            with self._lab_lock:
                last = self._last_chat_envelope.get(target)
            if last is None:
                reject(f"no previous chat message from {target} to replay yet")
                return
            detail = f"resent {target}'s most recent chat message a second time"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=target, armed_by=name)
            self._send(conn, {"type": "lab_control_result", "action": action, "target": target,
                              "armed": True, "detail": "resent immediately"})
            self._notify_armer(name, detail, action=action)
            self.route(dict(last), target)  # a copy: route() may tag the next pending action
            return

        with self._lab_lock:
            self._lab_pending[target] = (action, name)
        detail = {
            "tamper_next": f"next chat message from {target} will be tampered with",
            "drop_next": f"next chat message from {target} will be silently dropped",
            "mitm_next_handshake": f"next handshake started by {target} will have its "
                                   f"ECDH key substituted",
        }[action]
        print(f"    [LAB] armed by {name} from {addr[0]}: {detail}")
        self._send(conn, {"type": "lab_control_result", "action": action, "target": target,
                          "armed": True, "detail": detail})

    def _handle_get_pubkey(self, conn, envelope):
        """Answer a "get_pubkey" request directly from user_store -- this is
        a lookup of already-public information, not a route to another
        client, so it doesn't matter whether that user is currently online.
        """
        target_username = envelope.get("username")
        public_key_pem = get_public_key(target_username) if target_username else None
        self._send(conn, {
            "type": "pubkey_result",
            "username": target_username,
            "public_key": public_key_pem,
            "success": public_key_pem is not None,
        })

    def remove_client(self, conn):
        with self._lock:
            name = None
            for uname, c in list(self.clients.items()):
                if c is conn:
                    name = uname
                    del self.clients[uname]
                    break
        try:
            conn.close()
        except OSError:
            pass
        return name

    def _authenticate(self, conn, stream, addr):
        """Consume "register"/"login" envelopes until one succeeds, and
        return the authenticated username -- or None if the client
        disconnects before authenticating. Any other envelope type sent
        before authentication is rejected with a system message; the client
        is not admitted to the roster and cannot route chat/handshake
        envelopes until this returns a name.
        """
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                continue

            etype = envelope.get("type")
            if etype not in ("register", "login"):
                self._send_system(conn, "[!] Please register or login first.")
                continue

            # Stage D: a per-source-address rate limit covers BOTH register
            # and login attempts, independent of any one username -- this is
            # what catches an attacker spreading guesses across many
            # usernames, which the per-account lockout below alone would not.
            if not self.lockout.check_address_rate(addr[0]):
                self._send(conn, {
                    "type": f"{etype}_result", "success": False,
                    "reason": "too many requests from this address -- slow down and retry shortly",
                })
                log_event("address_rate_limited", from_addr=addr[0], attempted_type=etype)
                continue

            username = envelope.get("username")
            password = envelope.get("password")
            public_key_pem = envelope.get("public_key")
            result_type = f"{etype}_result"
            if not username or not password:
                self._send(conn, {
                    "type": result_type, "success": False,
                    "reason": "username and password are required",
                })
                continue

            if etype == "login":
                # Checked BEFORE verify_user() -- and therefore before any
                # PBKDF2 work -- so repeatedly hammering an already-locked
                # account cannot be used to burn CPU. See server/lockout.py's
                # module docstring for the enumeration-safety trade-off this
                # implies (the generic "invalid username or password" is
                # used right up through the failure that triggers the lock;
                # only an attempt against an ALREADY-locked account gets
                # this more specific message).
                lock_status = self.lockout.status(username)
                if lock_status.locked:
                    retry_after = int(lock_status.retry_after) + 1
                    self._send(conn, {
                        "type": "login_result", "success": False,
                        "reason": f"account temporarily locked, retry in {retry_after}s",
                    })
                    log_event("lockout_rejected", username=username, from_addr=addr[0],
                             retry_after=retry_after)
                    continue

            with self._lock:
                already_online = username in self.clients
            if already_online:
                self._send(conn, {
                    "type": result_type, "success": False,
                    "reason": f"'{username}' is already logged in elsewhere",
                })
                continue

            if etype == "register":
                if not register_user(username, password, public_key_pem=public_key_pem):
                    self._send(conn, {
                        "type": "register_result", "success": False,
                        "reason": f"username '{username}' is already taken",
                    })
                    continue
                self._send(conn, {
                    "type": "register_result", "success": True,
                    "reason": "registered and logged in",
                    "lab_mode": self.lab_mode,
                })
                print(f"[+] {username} registered from {addr[0]}:{addr[1]}")
                log_event("user_registered", username=username, from_addr=addr[0])
                return username
            else:  # login
                if not verify_user(username, password):
                    status = self.lockout.record_failure(username, addr=addr[0])
                    log_event("failed_login", username=username, from_addr=addr[0])
                    if status.newly_locked:
                        print(f"[!] {username} locked out after repeated failed logins "
                              f"(retry in {int(status.retry_after)}s)")
                        log_event("account_locked", username=username, from_addr=addr[0],
                                 retry_after=status.retry_after, lock_level=status.lock_level)
                    self._send(conn, {
                        "type": "login_result", "success": False,
                        "reason": "invalid username or password",
                    })
                    continue
                self.lockout.record_success(username)
                self._send(conn, {
                    "type": "login_result", "success": True,
                    "reason": "login successful",
                    "lab_mode": self.lab_mode,
                })
                print(f"[+] {username} logged in from {addr[0]}:{addr[1]}")
                log_event("user_login", username=username, from_addr=addr[0])
                return username
        return None

    def handle_client(self, conn, addr):
        name = None
        try:
            with conn.makefile("r", encoding="utf-8", newline="\n") as stream:
                name = self._authenticate(conn, stream, addr)
                if name is None:
                    return  # disconnected before authenticating

                with self._lock:
                    if name in self.clients:
                        # Raced with another connection for the same user
                        # between the authenticate check and here.
                        self._send_system(conn, f"[!] '{name}' is already logged in elsewhere.")
                        return
                    self.clients[name] = conn
                    roster = [u for u in self.clients if u != name]

                print(f"[+] {name} joined the roster from {addr[0]}:{addr[1]}")
                self._send(conn, {"type": "roster", "users": roster})
                self.broadcast_system(f"*** {name} joined the chat ***", exclude=conn)
                self.broadcast_event({"type": "user_joined", "username": name}, exclude=conn)

                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        envelope = json.loads(line)
                    except json.JSONDecodeError:
                        log_event("malformed_envelope", from_user=name, from_addr=addr[0],
                                 length=len(line))
                        continue

                    etype = envelope.get("type")
                    if etype in _RELAYED_TYPES:
                        self.route(envelope, name)
                    elif etype == "get_pubkey":
                        self._handle_get_pubkey(conn, envelope)
                    elif etype == "lab_control":
                        # Always intercepted (never silently ignored like a
                        # genuinely unknown type) so a rejected attempt is
                        # always logged -- see _handle_lab_control.
                        self._handle_lab_control(conn, addr, name, envelope)
                    elif etype == "security_alert":
                        # Stage D: a client reporting that IT caught an
                        # attack (GCM/signature/replay/chain/handshake). We
                        # only log the metadata already in the envelope --
                        # never re-derive or store anything sensitive -- and
                        # never relay it anywhere; it's purely for the
                        # security dashboard. See client.py's
                        # _send_security_alert for exactly what it contains
                        # and the "a malicious relay could drop this too"
                        # limitation that's documented there.
                        log_event("security_alert", reported_by=name, from_addr=addr[0],
                                 alert=envelope.get("alert"), reason=envelope.get("reason"),
                                 peer=envelope.get("peer"), seq=envelope.get("seq"))
                    # Unknown/unsupported types are ignored -- the server
                    # only understands routing, never message content.
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            removed = self.remove_client(conn)
            if removed:
                print(f"[-] {removed} disconnected")
                self.broadcast_system(f"*** {removed} left the chat ***")

    def _handle_raw_connection(self, conn, addr):
        """Perform the TLS handshake for one accepted raw connection, then
        hand off to handle_client. Runs in its own thread (spawned right
        after accept(), before any handshake happens) so one slow or hostile
        TLS handshake -- or a client that never speaks TLS at all -- blocks
        only this thread, never the accept loop or other clients.
        """
        try:
            tls_conn = self.ssl_context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            print(f"[!] TLS handshake failed with {addr[0]}:{addr[1]} -- {exc}")
            log_event("non_tls_connection", from_addr=addr[0], reason=str(exc))
            try:
                conn.close()
            except OSError:
                pass
            return
        # One handler thread reads this connection while other handler
        # threads route()/broadcast into it -- see transport/locked_tls.py.
        safe_conn = LockedTLSSocket(tls_conn)
        with self._lock:
            self._open_conns.add(safe_conn)
        try:
            self.handle_client(safe_conn, addr)
        finally:
            with self._lock:
                self._open_conns.discard(safe_conn)

    def listen(self):
        """Bind and start listening, then return the real port. Idempotent.

        Pass port=0 to let the OS pick a free port (read it back from the
        return value or self.port): there is no window between "find a free
        port" and "bind it" for another process to steal it, unlike the old
        free_port()-then-bind dance. Because the socket is already listening
        when this returns, a client may connect immediately -- callers need no
        "wait until the port accepts connections" polling (whose raw probe
        connections also just generated spurious TLS-handshake failures)."""
        if self._srv is not None:
            return self.port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen()
        except OSError:
            srv.close()
            raise
        self.port = srv.getsockname()[1]
        self._srv = srv
        return self.port

    def shutdown(self):
        """Ask serve_forever() to return, and force every open connection
        closed. Safe to call more than once, from any thread."""
        self._stop.set()
        with self._lock:
            conns = list(self._open_conns)
        for conn in conns:
            conn.close()

    def serve_forever(self):
        self.listen()
        srv = self._srv
        srv.settimeout(0.2)  # so shutdown() is noticed promptly
        print(f"[*] Server listening on {self.host}:{self.port} over TLS "
              f"(cert fingerprint: {self.cert_fingerprint}) "
              f"(routes handshake/chat envelopes; never sees plaintext app "
              f"secrets or session keys)")
        if self.lab_mode:
            print("[*] LAB MODE ENABLED -- localhost, authenticated clients may arm "
                  "one-shot relay attacks via lab_control. Never enable this on a "
                  "server reachable from anywhere but localhost.")
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break  # listening socket closed
                threading.Thread(
                    target=self._handle_raw_connection, args=(conn, addr), daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down")
        finally:
            self._stop.set()
            srv.close()
            self._srv = None
            self.shutdown()
            with self._lock:
                conns = list(self.clients.values())
            for conn in conns:
                self.remove_client(conn)


def main():
    parser = argparse.ArgumentParser(description="Secure chat relay server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--certfile", default=DEFAULT_CERT_PATH)
    parser.add_argument("--keyfile", default=DEFAULT_KEY_PATH)
    parser.add_argument("--lab", action="store_true",
                         help="enable the opt-in Attack Lab (lab_control envelopes from "
                              "authenticated localhost clients only); OFF by default")
    args = parser.parse_args()
    try:
        server = ChatServer(args.host, args.port, args.certfile, args.keyfile,
                            lab_mode=args.lab)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        sys.exit(1)
    server.serve_forever()


if __name__ == "__main__":
    main()
