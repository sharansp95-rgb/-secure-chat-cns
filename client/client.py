"""Phase 1 baseline chat client: plaintext TCP.

Sends on the main thread (reading stdin) and receives on a background thread so
incoming messages print without blocking what the user is typing.

Wire format: one UTF-8 message per line, terminated by '\n'. The first line
sent after connecting is the username.
"""

import argparse
import socket
import sys
import threading

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def receive_loop(sock, stop_event):
    """Print everything the server relays until the connection closes."""
    try:
        with sock.makefile("r", encoding="utf-8", newline="\n") as stream:
            for line in stream:
                if stop_event.is_set():
                    break
                text = line.rstrip("\n")
                if text:
                    # \r clears the prompt so incoming text doesn't collide
                    # with a half-typed line.
                    print(f"\r{text}\n> ", end="", flush=True)
    except (OSError, ValueError):
        pass
    finally:
        if not stop_event.is_set():
            print("\r[!] Disconnected from server.", flush=True)
        stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="Phase 1 plaintext chat client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--username", help="skip the username prompt")
    args = parser.parse_args()

    username = args.username or input("Username: ").strip()
    if not username:
        print("A username is required.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except OSError as exc:
        print(f"[!] Could not connect to {args.host}:{args.port} -- {exc}")
        sys.exit(1)

    sock.sendall((username + "\n").encode("utf-8"))
    print(f"[*] Connected to {args.host}:{args.port} as {username}. "
          f"Type a message and press Enter (Ctrl-C to quit).")

    stop_event = threading.Event()
    threading.Thread(
        target=receive_loop, args=(sock, stop_event), daemon=True
    ).start()

    try:
        while not stop_event.is_set():
            try:
                text = input("> ")
            except EOFError:
                break
            if not text.strip():
                continue
            if stop_event.is_set():
                break
            try:
                sock.sendall((text + "\n").encode("utf-8"))
            except OSError:
                print("[!] Send failed; connection lost.")
                break
    except KeyboardInterrupt:
        print()
    finally:
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("[*] Disconnected.")


if __name__ == "__main__":
    main()
