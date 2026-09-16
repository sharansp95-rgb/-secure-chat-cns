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


class ChatServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 certfile=DEFAULT_CERT_PATH, keyfile=DEFAULT_KEY_PATH):
        self.host = host
        self.port = port
        # Built eagerly (not lazily in serve_forever) so a missing-certs
        # error surfaces immediately when the server is constructed, not
        # buried inside the accept loop.
        self.ssl_context = build_server_ssl_context(certfile, keyfile)
        # username -> conn (the TLS-wrapped socket). Guarded by _lock: every
        # client thread mutates it on join/leave and reads it on every
        # route/broadcast.
        self.clients = {}
        self._lock = threading.Lock()

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

    def route(self, envelope, sender_name):
        """Forward a handshake/chat envelope to its named recipient only."""
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
                })
                print(f"[+] {username} registered from {addr[0]}:{addr[1]}")
                return username
            else:  # login
                if not verify_user(username, password):
                    self._send(conn, {
                        "type": "login_result", "success": False,
                        "reason": "invalid username or password",
                    })
                    continue
                self._send(conn, {
                    "type": "login_result", "success": True,
                    "reason": "login successful",
                })
                print(f"[+] {username} logged in from {addr[0]}:{addr[1]}")
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
                        continue

                    etype = envelope.get("type")
                    if etype in _RELAYED_TYPES:
                        self.route(envelope, name)
                    elif etype == "get_pubkey":
                        self._handle_get_pubkey(conn, envelope)
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
            try:
                conn.close()
            except OSError:
                pass
            return
        self.handle_client(tls_conn, addr)

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen()
            print(f"[*] Server listening on {self.host}:{self.port} over TLS "
                  f"(routes handshake/chat envelopes; never sees plaintext app "
                  f"secrets or session keys)")
            try:
                while True:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self._handle_raw_connection, args=(conn, addr), daemon=True
                    ).start()
            except KeyboardInterrupt:
                print("\n[*] Shutting down")
            finally:
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
    args = parser.parse_args()
    try:
        server = ChatServer(args.host, args.port, args.certfile, args.keyfile)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        sys.exit(1)
    server.serve_forever()


if __name__ == "__main__":
    main()
