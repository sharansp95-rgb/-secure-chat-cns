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

SECURITY NOTE (Phase 4 -> Phase 6 gap): "register"/"login" envelopes carry the
password itself (so it can be hashed/checked server-side) in plain JSON. The
Phase 3 AES-GCM session key only protects *chat* payloads between two peers
that have already completed a handshake -- it does not exist yet at login
time, and it wouldn't cover the client<->server leg anyway. That means the
raw TCP socket the register/login envelope travels over is NOT yet encrypted
at this phase; a network observer between client and server could see a
password in transit. This is a known, deliberate gap: wrapping the whole
socket in TLS is exactly Phase 6's job, and we are not trying to work around
it early with an ad hoc fix here.

Wire format: one UTF-8 JSON object per line (newline-terminated). Every
envelope has a "type" field. Envelopes that name a "to" recipient are
unicast to that user if online; everything else (register, login, roster) is
handled directly by the server.
"""

import argparse
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from user_store import register_user, verify_user
except ImportError:  # running as part of the `server` package (e.g. tests)
    from server.user_store import register_user, verify_user

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

# Envelope types relayed verbatim to a specific "to" recipient without the
# server inspecting their payload beyond routing fields.
_RELAYED_TYPES = {"handshake_init", "handshake_response", "chat"}


class ChatServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        # username -> conn. Guarded by _lock: every client thread mutates it
        # on join/leave and reads it on every route/broadcast.
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
                if not register_user(username, password):
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
                    # Unknown/unsupported types are ignored -- the server
                    # only understands routing, never message content.
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            removed = self.remove_client(conn)
            if removed:
                print(f"[-] {removed} disconnected")
                self.broadcast_system(f"*** {removed} left the chat ***")

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen()
            print(f"[*] Server listening on {self.host}:{self.port} "
                  f"(routes handshake/chat envelopes; never sees plaintext or keys)")
            try:
                while True:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self.handle_client, args=(conn, addr), daemon=True
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
    args = parser.parse_args()
    ChatServer(args.host, args.port).serve_forever()


if __name__ == "__main__":
    main()
