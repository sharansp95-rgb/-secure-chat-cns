"""Phase 1 baseline relay server: threaded TCP, plaintext.

Accepts multiple simultaneous clients and relays every message it receives to
all the *other* connected clients. No encryption at this stage -- this is the
skeleton that Phase 3+ will wrap in a negotiated session key.

Wire format: one UTF-8 message per line, terminated by '\n'.
"""

import argparse
import socket
import threading

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


class ChatServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        # conn -> display name. Guarded by _lock because every client thread
        # mutates it on join/leave and reads it on every broadcast.
        self.clients = {}
        self._lock = threading.Lock()

    def broadcast(self, message, sender=None):
        """Send message to every client except `sender`."""
        payload = (message + "\n").encode("utf-8")
        with self._lock:
            targets = [c for c in self.clients if c is not sender]
        for conn in targets:
            try:
                conn.sendall(payload)
            except OSError:
                # Peer vanished mid-send; its own thread will clean it up.
                self.remove_client(conn)

    def remove_client(self, conn):
        with self._lock:
            name = self.clients.pop(conn, None)
        try:
            conn.close()
        except OSError:
            pass
        return name

    def handle_client(self, conn, addr):
        name = None
        try:
            with conn.makefile("r", encoding="utf-8", newline="\n") as stream:
                first = stream.readline()
                if not first:
                    return
                name = first.strip() or f"{addr[0]}:{addr[1]}"
                with self._lock:
                    self.clients[conn] = name
                print(f"[+] {name} connected from {addr[0]}:{addr[1]}")
                self.broadcast(f"*** {name} joined the chat ***", sender=conn)

                for line in stream:
                    text = line.rstrip("\n")
                    if not text:
                        continue
                    print(f"[{name}] {text}")
                    self.broadcast(f"{name}: {text}", sender=conn)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # Abrupt disconnect is normal; fall through to cleanup.
            pass
        finally:
            removed = self.remove_client(conn)
            if removed:
                print(f"[-] {removed} disconnected")
                self.broadcast(f"*** {removed} left the chat ***")

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen()
            print(f"[*] Server listening on {self.host}:{self.port} (plaintext)")
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
                    conns = list(self.clients)
                for conn in conns:
                    self.remove_client(conn)


def main():
    parser = argparse.ArgumentParser(description="Phase 1 plaintext chat server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    ChatServer(args.host, args.port).serve_forever()


if __name__ == "__main__":
    main()
