"""Tkinter GUI chat client.

Reuses client/client.py's SecureChatClient, connect_tls, keystore, and
signature helpers directly -- this file contains NO protocol, crypto, or
networking logic of its own. It is purely a presentation layer: a normal-
looking chat window for the plaintext conversation, plus a second "Wire Log"
panel that shows exactly what's actually crossing the network at each step
(handshake public keys + signature verification results, each message's
ciphertext/tag, fingerprints, and any rejected/tampered message) -- making
the cryptography the rest of this project implements visible instead of
invisible.

Threading model: all socket I/O (connecting, registering/logging in,
sending, and SecureChatClient's own receive_loop) happens on background
threads. SecureChatClient's event_callback (see client/client.py) is called
from those background threads, so it never touches a Tk widget directly --
it only pushes (kind, data) onto a plain, thread-safe queue.Queue. The Tk
main loop drains that queue on a `root.after()` timer and does all actual
widget updates there. This is the standard safe pattern for Tkinter +
background threads (Tkinter itself is not thread-safe).

Run:  python gui/chat_gui.py
"""

import json
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.keystore import load_private_key, save_private_key  # noqa: E402
from client.client import (  # noqa: E402
    DEFAULT_HOST,
    DEFAULT_PORT,
    SecureChatClient,
    TLSSetupError,
    connect_tls,
)
from crypto_engine.signatures import fingerprint  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import serialize_public_key  # noqa: E402

POLL_INTERVAL_MS = 50
WIRE_LOG_TRUNCATE = 32

# Envelope fields that are genuinely sensitive if shown in the clear in a
# teaching demo -- the password *is* protected on the real wire by TLS
# (Phase 6), but this GUI operates above that layer (it builds the plaintext
# JSON dict that the OS/ssl module then encrypts), so if we didn't redact it
# here the wire log would show something that looks like a leak even though
# it isn't one on the actual network. Nothing else needs this treatment: a
# chat envelope's own fields (nonce/ciphertext/tag) never contain plaintext
# to begin with.
_REDACT_FIELDS = {"password"}


def _truncate(s, n=WIRE_LOG_TRUNCATE):
    return s if len(s) <= n else s[:n] + "..."


def _redact_envelope(envelope):
    return {k: ("***redacted (protected by TLS in transit)***" if k in _REDACT_FIELDS else v)
            for k, v in envelope.items()}


def format_envelope_line(direction, envelope):
    """Render one JSON envelope as a short, readable wire-log line. Returns
    (text, is_warning). `direction` is "-->" (sent) or "<--" (received)."""
    etype = envelope.get("type", "?")
    e = _redact_envelope(envelope)

    if etype in ("register", "login"):
        parts = [f"username={e.get('username')}"]
        if "public_key" in e:
            parts.append(f"public_key={_truncate(e['public_key'].replace(chr(10), ' '))}")
        if "password" in e:
            parts.append(f"password={e['password']}")
        return f"{direction} {etype}: " + ", ".join(parts), False

    if etype in ("register_result", "login_result"):
        ok = e.get("success")
        return f"{direction} {etype}: success={ok}, reason={e.get('reason')}", not ok

    if etype in ("handshake_init", "handshake_response"):
        return (
            f"{direction} {etype}: from={e.get('from')} to={e.get('to')} "
            f"pubkey={_truncate(e.get('pubkey', ''))} "
            f"sig={_truncate(e.get('handshake_sig', ''))}",
            False,
        )

    if etype == "get_pubkey":
        return f"{direction} get_pubkey: username={e.get('username')}", False

    if etype == "pubkey_result":
        return (
            f"{direction} pubkey_result: username={e.get('username')} "
            f"success={e.get('success')}",
            not e.get("success", True),
        )

    if etype == "chat":
        return (
            f"{direction} chat: from={e.get('from')} "
            f"nonce={_truncate(e.get('nonce', ''))} "
            f"ciphertext={_truncate(e.get('ciphertext', ''))} "
            f"tag={_truncate(e.get('tag', ''))}",
            False,
        )

    if etype == "system":
        return f"{direction} system: {e.get('text', '')}", False

    if etype == "roster":
        return f"{direction} roster: users={e.get('users')}", False

    if etype == "user_joined":
        return f"{direction} user_joined: {e.get('username')}", False

    return f"{direction} {etype}: {json.dumps(e)[:120]}", False


class ChatGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat (GUI)")
        self.geometry("980x620")
        self.minsize(760, 480)

        # Thread-safe: SecureChatClient's event_callback (invoked from
        # background threads) only ever does event_queue.put(...). All
        # actual widget updates happen in _poll_events, on the main thread.
        self.event_queue = queue.Queue()

        self.client = None       # SecureChatClient, once connected
        self.sock = None
        self.username = None
        self.peer = None

        self._build_login_screen()
        self._build_chat_screen()
        self._show_login_screen()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(POLL_INTERVAL_MS, self._poll_events)

    # --- screen scaffolding -------------------------------------------

    def _build_login_screen(self):
        frame = ttk.Frame(self, padding=24)
        self.login_frame = frame

        ttk.Label(frame, text="Secure Chat -- Login / Register",
                  font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 16))

        fields = [
            ("Server host:", "host_var", DEFAULT_HOST),
            ("Server port:", "port_var", str(DEFAULT_PORT)),
            ("Username:", "username_var", ""),
            ("Peer username:", "peer_var", ""),
        ]
        for i, (label, attr, default) in enumerate(fields, start=1):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="e", pady=4, padx=(0, 8))
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            ttk.Entry(frame, textvariable=var, width=30).grid(row=i, column=1, sticky="w", pady=4)

        row = len(fields) + 1
        ttk.Label(frame, text="Password:").grid(row=row, column=0, sticky="e", pady=4, padx=(0, 8))
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*", width=30).grid(
            row=row, column=1, sticky="w", pady=4)

        button_row = row + 1
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=button_row, column=0, columnspan=2, pady=(16, 4))
        self.register_button = ttk.Button(button_frame, text="Register",
                                           command=lambda: self._start_auth("register"))
        self.register_button.pack(side="left", padx=4)
        self.login_button = ttk.Button(button_frame, text="Login",
                                        command=lambda: self._start_auth("login"))
        self.login_button.pack(side="left", padx=4)

        self.login_status_var = tk.StringVar(value="")
        self.login_status_label = ttk.Label(frame, textvariable=self.login_status_var,
                                             foreground="#a80000", wraplength=420)
        self.login_status_label.grid(row=button_row + 1, column=0, columnspan=2, pady=(8, 0))

    def _build_chat_screen(self):
        frame = ttk.Frame(self)
        self.chat_frame = frame

        # -- top bar: fingerprint, prominent, for out-loud comparison --
        top = ttk.Frame(frame, padding=(10, 8))
        top.pack(side="top", fill="x")
        self.header_var = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.header_var, font=("Segoe UI", 11, "bold")).pack(
            side="left")
        self.fingerprint_var = tk.StringVar(value="Fingerprint: (handshake not complete yet)")
        ttk.Label(top, textvariable=self.fingerprint_var, font=("Consolas", 11, "bold"),
                  foreground="#0b5fa5").pack(side="right")

        self.conn_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.conn_status_var, foreground="#a80000",
                  padding=(10, 0)).pack(side="top", fill="x")

        # -- split pane: plaintext chat (left) / wire log (right) --
        paned = ttk.Panedwindow(frame, orient="horizontal")
        paned.pack(side="top", fill="both", expand=True, padx=8, pady=8)

        chat_pane = ttk.Frame(paned)
        ttk.Label(chat_pane, text="Conversation (what you see)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.chat_text = tk.Text(chat_pane, wrap="word", state="disabled", height=20)
        self.chat_text.pack(side="top", fill="both", expand=True)
        self.chat_text.tag_config("me", foreground="#0b5fa5")
        self.chat_text.tag_config("peer", foreground="#1a7a1a")
        self.chat_text.tag_config("system", foreground="#666666", font=("Segoe UI", 9, "italic"))
        self.chat_text.tag_config("warning", foreground="#c00000", font=("Segoe UI", 9, "bold"))
        paned.add(chat_pane, weight=1)

        wire_pane = ttk.Frame(paned)
        ttk.Label(wire_pane, text="Wire Log (what actually crosses the network)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.wire_text = tk.Text(wire_pane, wrap="word", state="disabled", height=20,
                                  font=("Consolas", 9), background="#0f1117", foreground="#d0d0d0")
        self.wire_text.pack(side="top", fill="both", expand=True)
        self.wire_text.tag_config("sent", foreground="#7fc7ff")
        self.wire_text.tag_config("recv", foreground="#b6f27f")
        self.wire_text.tag_config("warning", foreground="#ff5c5c", font=("Consolas", 9, "bold"))
        self.wire_text.tag_config("info", foreground="#d0d0d0")
        paned.add(wire_pane, weight=1)

        # -- entry + send --
        entry_frame = ttk.Frame(frame, padding=(8, 0, 8, 8))
        entry_frame.pack(side="bottom", fill="x")
        self.message_var = tk.StringVar()
        entry = ttk.Entry(entry_frame, textvariable=self.message_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._on_send())
        self.send_button = ttk.Button(entry_frame, text="Send", command=self._on_send)
        self.send_button.pack(side="left", padx=(6, 0))

    def _show_login_screen(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def _show_chat_screen(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)

    # --- login / register (background thread) --------------------------

    def _start_auth(self, mode):
        host = self.host_var.get().strip() or DEFAULT_HOST
        try:
            port = int(self.port_var.get().strip() or DEFAULT_PORT)
        except ValueError:
            self.login_status_var.set("Port must be a number.")
            return
        username = self.username_var.get().strip()
        peer = self.peer_var.get().strip()
        password = self.password_var.get()

        if not username or not peer or not password:
            self.login_status_var.set("Username, peer, and password are all required.")
            return

        self.register_button.config(state="disabled")
        self.login_button.config(state="disabled")
        self.login_status_var.set("Connecting...")

        threading.Thread(
            target=self._auth_worker, args=(mode, host, port, username, peer, password),
            daemon=True,
        ).start()

    def _auth_worker(self, mode, host, port, username, peer, password):
        """Runs entirely on a background thread: connect, register/login,
        (for register) generate+save an RSA identity, then fetch the peer's
        public key -- exactly what client.py's authenticate()/main() do for
        the terminal client, just without any input()/print()."""
        try:
            sock = connect_tls(host, port)
        except TLSSetupError as exc:
            self.event_queue.put(("auth_error", {"detail": str(exc)}))
            return

        client = SecureChatClient(sock, username=username, peer=peer,
                                   event_callback=self._on_client_event)
        threading.Thread(target=client.receive_loop, daemon=True).start()

        rsa_private_key = None
        if mode == "register":
            rsa_private_key, rsa_public_key = generate_rsa_keypair()
            public_key_pem = serialize_public_key(rsa_public_key).decode("ascii")
            client.register(username, password, public_key_pem=public_key_pem)
        else:
            client.login(username, password)

        result = client.auth_results.get()
        if not result or not result.get("success"):
            reason = result.get("reason") if result else "connection lost"
            self.event_queue.put(("auth_error", {"detail": reason}))
            try:
                sock.close()
            except OSError:
                pass
            return

        if mode == "register":
            save_private_key(username, rsa_private_key)
            client.rsa_private_key = rsa_private_key
        else:
            client.rsa_private_key = load_private_key(username)

        own_fingerprint = None
        if client.rsa_private_key is not None:
            own_pem = serialize_public_key(client.rsa_private_key.public_key())
            own_fingerprint = fingerprint(own_pem)

        peer_key_found = client.fetch_peer_public_key()

        self.client = client
        self.sock = sock
        self.username = username
        self.peer = peer
        self.event_queue.put(("auth_success", {
            "username": username, "peer": peer,
            "own_fingerprint": own_fingerprint, "peer_key_found": peer_key_found,
        }))

    # --- sending ---------------------------------------------------------

    def _on_send(self):
        if self.client is None:
            return
        text = self.message_var.get()
        if not text.strip():
            return
        self.message_var.set("")
        threading.Thread(target=self.client.send_message, args=(text,), daemon=True).start()

    # --- SecureChatClient event hook (background thread!) ---------------

    def _on_client_event(self, kind, data):
        """Called from SecureChatClient's receive_loop (or an auth/send
        worker) thread. Must never touch a Tk widget directly -- only ever
        queues the event for _poll_events to handle on the main thread."""
        self.event_queue.put((kind, data))

    # --- main-thread event draining (Tk-safe) ---------------------------

    def _poll_events(self):
        try:
            while True:
                kind, data = self.event_queue.get_nowait()
                self._handle_event(kind, data)
        except queue.Empty:
            pass
        self.after(POLL_INTERVAL_MS, self._poll_events)

    def _handle_event(self, kind, data):
        if kind == "auth_error":
            self.login_status_var.set(f"Failed: {data.get('detail')}")
            self.register_button.config(state="normal")
            self.login_button.config(state="normal")
            return

        if kind == "auth_success":
            self.header_var.set(f"Logged in as {data['username']}  --  chatting with {data['peer']}")
            if data.get("own_fingerprint"):
                self._append_chat(f"[system] Your key fingerprint: {data['own_fingerprint']}",
                                   "system")
            if not data.get("peer_key_found"):
                self._append_chat(
                    f"[system] Could not fetch {data['peer']}'s public key yet -- their "
                    f"messages will be rejected until this client reconnects after they "
                    f"register.", "warning")
            self._show_chat_screen()
            return

        if kind == "envelope_sent":
            text, is_warning = format_envelope_line("-->", data["envelope"])
            self._append_wire(text, "warning" if is_warning else "sent")
            return

        if kind == "envelope_received":
            text, is_warning = format_envelope_line("<--", data["envelope"])
            self._append_wire(text, "warning" if is_warning else "recv")
            return

        if kind == "handshake_started":
            self._append_wire(f"[handshake] starting ECDH key exchange with {data['peer']}...",
                               "info")
            return

        if kind == "handshake_waiting":
            self._append_wire(
                f"[handshake] waiting on {data['peer']}'s RSA public key to verify "
                f"an incoming handshake message...", "info")
            return

        if kind == "handshake_established":
            self._append_wire(f"[handshake] session key established with {data['peer']} "
                               f"(ECDH, authenticated by RSA signature)", "info")
            self._append_chat(f"[system] Secure session established with {data['peer']}.",
                               "system")
            return

        if kind == "handshake_aborted":
            msg = f"[handshake] ABORTED with {data['peer']}: {data['reason']}"
            self._append_wire(msg, "warning")
            self._append_chat("[system] " + msg, "warning")
            return

        if kind == "peer_fingerprint":
            fp = data["fingerprint"]
            self.fingerprint_var.set(f"{data['peer']}'s fingerprint: {fp}")
            self._append_wire(f"[handshake] {data['peer']}'s RSA key fingerprint: {fp}", "info")
            return

        if kind == "message_sent":
            self._append_chat(f"me: {data['message']}", "me")
            return

        if kind == "message_queued":
            self._append_chat(f"[system] Message queued until the secure session is ready: "
                               f"{data['message']}", "system")
            return

        if kind == "message_received":
            self._append_chat(f"{data['sender']}: {data['message']}", "peer")
            return

        if kind == "message_rejected":
            msg = f"[!] REJECTED message from {data['sender']}: {data['detail']}"
            self._append_chat(msg, "warning")
            self._append_wire(msg, "warning")
            return

        if kind == "system_message":
            self._append_chat(f"[system] {data['text']}", "system")
            return

        if kind == "disconnected":
            self.conn_status_var.set(f"Disconnected from server: {data.get('reason', '')}")
            self._append_chat("[system] Disconnected from server.", "warning")
            return

    # --- small text-widget helpers ---------------------------------------

    def _append_chat(self, line, tag=None):
        self.chat_text.config(state="normal")
        self.chat_text.insert("end", line + "\n", (tag,) if tag else ())
        self.chat_text.see("end")
        self.chat_text.config(state="disabled")

    def _append_wire(self, line, tag=None):
        timestamp = time.strftime("%H:%M:%S")
        self.wire_text.config(state="normal")
        self.wire_text.insert("end", f"[{timestamp}] {line}\n", (tag,) if tag else ())
        self.wire_text.see("end")
        self.wire_text.config(state="disabled")

    # --- shutdown ----------------------------------------------------------

    def _on_close(self):
        if self.client is not None:
            self.client.stop_event.set()
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.destroy()


def main():
    app = ChatGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
