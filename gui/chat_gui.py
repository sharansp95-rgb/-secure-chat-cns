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

Visual design: dark theme, WhatsApp-style message bubbles, font-availability
fallback -- see gui/theme.py's Theme class (shared with
gui/security_dashboard.py). This is presentation only; nothing in this
section touches SecureChatClient or the event shape.

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
from client.evidence import EvidenceError  # noqa: E402
from crypto_engine.signatures import fingerprint  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import serialize_public_key  # noqa: E402
from gui import widgets  # noqa: E402
from gui.explain import describe_rejection  # noqa: E402
from gui.theme import Theme  # noqa: E402

POLL_INTERVAL_MS = 50
TAGLINE = "Accountable end-to-end encrypted messaging for hospitals"
NETWORK_MIN_WIDTH = 860       # narrower windows start with the network view hidden
HANDOFF_WAIT_MS = 2500        # how long the login screen waits for the handshake to finish
HANDOFF_PEER_OFFLINE_MS = 1300
LOGIN_STEP_KINDS = ("tls_connected", "tls_cert_fingerprint", "handshake_started",
                    "handshake_established", "handshake_waiting")
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


def WIRE_COLORS(theme):
    """Colour of each kind of line in the network view."""
    return {"TLS": theme.wire_tls, "HANDSHAKE": theme.wire_handshake, "CHAT": theme.wire_chat,
            "ALERT": theme.wire_alert, "AUTH": theme.wire_auth, "INFO": theme.wire_info}


def wire_kind(envelope):
    """Which kind of network-view line an envelope is."""
    etype = envelope.get("type", "")
    if etype in ("handshake_init", "handshake_response", "get_pubkey", "pubkey_result"):
        return "HANDSHAKE"
    if etype == "chat":
        return "CHAT"
    if etype in ("register", "login", "register_result", "login_result"):
        return "AUTH"
    if etype in ("security_alert", "lab_control", "lab_control_result", "lab_attack_performed"):
        return "ALERT"
    return "INFO"


def validate_login_form(host, port, username, peer, password):
    """Inline validation for the login form. Returns {field: message} for every problem
    (empty dict = OK); fields are "port", "username", "peer", "password"."""
    errors = {}
    port = str(port).strip()
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        errors["port"] = "Port must be a number from 1 to 65535."
    if not username.strip():
        errors["username"] = "Enter your username."
    if not peer.strip():
        errors["peer"] = "Enter who you want to chat with."
    elif peer.strip() == username.strip():
        errors["peer"] = "The peer must be someone else."
    if not password:
        errors["password"] = "Enter your password."
    return errors


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
            f"pubkey={_truncate(e.get('pubkey', ''), 14)} "
            f"sig={_truncate(e.get('handshake_sig', ''), 14)}",
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
            f"nonce={_truncate(e.get('nonce', ''), 12)} "
            f"ciphertext={_truncate(e.get('ciphertext', ''), 12)} "
            f"tag={_truncate(e.get('tag', ''), 12)}",
            False,
        )

    if etype == "system":
        return f"{direction} system: {e.get('text', '')}", False

    if etype == "roster":
        return f"{direction} roster: users={e.get('users')}", False

    if etype == "lab_control":
        return f"{direction} lab_control: action={e.get('action')} target={e.get('target')}", False

    if etype == "lab_control_result":
        armed = e.get("armed")
        return (f"{direction} lab_control_result: action={e.get('action')} armed={armed} "
               f"-- {e.get('detail')}", not armed)

    if etype == "lab_attack_performed":
        return f"{direction} lab_attack_performed: {e.get('detail')}", True

    if etype == "user_joined":
        return f"{direction} user_joined: {e.get('username')}", False

    return f"{direction} {etype}: {json.dumps(e)[:120]}", False


class ChatGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat (GUI)")
        self.geometry("1040x660")
        self.minsize(680, 460)

        self.theme = Theme(self)
        self.configure(background=self.theme.bg_app)
        style = ttk.Style(self)
        self.theme.apply_ttk(style)

        # Thread-safe: SecureChatClient's event_callback (invoked from
        # background threads) only ever does event_queue.put(...). All
        # actual widget updates happen in _poll_events, on the main thread.
        self.event_queue = queue.Queue()

        self.client = None       # SecureChatClient, once connected
        self.sock = None
        self.username = None
        self.peer = None
        self._auth_data = None       # auth_success payload, while the login screen waits
        self._held_events = []       # events that arrived during that wait (replayed in order)
        self._holding = False
        self._chat_ready = False     # the chat screen has been shown (events are applied live)
        self._handshake_done = False
        self._tls_fingerprint = None
        self._login_mode = "login"

        self._build_login_screen()
        self._build_chat_screen()
        self._show_login_screen()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(POLL_INTERVAL_MS, self._poll_events)

    # --- screen scaffolding -------------------------------------------

    def _build_login_screen(self):
        t = self.theme
        outer = tk.Frame(self, background=t.bg_app)
        self.login_frame = outer

        card = widgets.make_card(outer, t, padx="xl", pady="lg")
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.columnconfigure(0, weight=1)

        # -- brand row: drawn shield + name + tagline --
        brand = tk.Frame(card, background=t.bg_panel)
        brand.grid(row=0, column=0, sticky="ew", pady=(0, t.sp("lg")))
        widgets.Logo(brand, t, size=t.sp(56)).pack(side="left", padx=(0, t.sp("md")))
        names = tk.Frame(brand, background=t.bg_panel)
        names.pack(side="left", fill="x", expand=True)
        tk.Label(names, text="Secure Chat", background=t.bg_panel, foreground=t.fg_primary,
                 font=t.font("title"), anchor="w").pack(anchor="w")
        tk.Label(names, text=TAGLINE, background=t.bg_panel, foreground=t.fg_secondary,
                 font=t.font("caption"), wraplength=300, justify="left", anchor="w").pack(anchor="w")

        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.username_var = tk.StringVar()
        self.peer_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self._fields, self._field_errors = {}, {}
        self._form_groups = []     # widgets hidden while connecting (see _set_login_busy)
        self._login_row = 1

        def add_field(key, label, var, hint="", show="", trailing=None):
            # The label row has one right-hand slot: the hint, replaced by a red inline
            # error when validation fails (so errors never change the card's height).
            row = tk.Frame(card, background=t.bg_panel)
            row.grid(row=self._login_row, column=0, sticky="ew")
            tk.Label(row, text=label, background=t.bg_panel, foreground=t.fg_primary,
                     font=t.font("body_bold")).pack(side="left")
            hint_lbl = tk.Label(row, text=hint, background=t.bg_panel, foreground=t.fg_hint,
                                font=t.font("caption"))
            hint_lbl.pack(side="right")
            err = tk.Label(row, text="", background=t.bg_panel, foreground=t.danger,
                           font=t.font("caption_bold"))
            field = widgets.Field(card, t, var, show=show, width=30, trailing=trailing)
            field.grid(row=self._login_row + 1, column=0, sticky="ew",
                       pady=(t.sp("xs"), t.sp("sm")))
            self._form_groups += [row, field]
            err._hint = hint_lbl
            self._fields[key], self._field_errors[key] = field, err
            self._login_row += 2
            return field

        add_field("username", "Username", self.username_var, "your name in this chat")
        add_field("peer", "Peer username", self.peer_var, "the other window's user")

        def toggle(parent):
            self._pw_toggle = tk.Label(parent, text="Show", background=t.bg_input,
                                       foreground=t.accent, font=t.font("caption_bold"),
                                       cursor="pointinghand")
            self._pw_toggle.bind("<Button-1>", lambda _e: self._toggle_password())
            return self._pw_toggle
        add_field("password", "Password", self.password_var, show="•", trailing=toggle)

        # Server settings stay out of the way (they are set once by the launcher) but are
        # one click away, and open by themselves if the port is invalid.
        self._server_open = False
        self.server_toggle = tk.Label(card, text="", background=t.bg_panel, foreground=t.fg_hint,
                                      font=t.font("caption"), cursor="pointinghand", anchor="w")
        self.server_toggle.grid(row=self._login_row, column=0, sticky="w", pady=(t.sp("xs"), 0))
        self.server_toggle.bind("<Button-1>", lambda _e: self._toggle_server_settings())
        self._form_groups.append(self.server_toggle)
        self._login_row += 1
        self.server_box = tk.Frame(card, background=t.bg_panel)
        self.server_box.grid(row=self._login_row, column=0, sticky="ew")
        tk.Label(self.server_box, text="Host", background=t.bg_panel, foreground=t.fg_secondary,
                 font=t.font("caption")).grid(row=0, column=0, sticky="w")
        tk.Label(self.server_box, text="Port", background=t.bg_panel, foreground=t.fg_secondary,
                 font=t.font("caption")).grid(row=0, column=1, sticky="w", padx=(t.sp("sm"), 0))
        host_field = widgets.Field(self.server_box, t, self.host_var, width=18)
        host_field.grid(row=1, column=0, sticky="ew")
        port_field = widgets.Field(self.server_box, t, self.port_var, width=6)
        port_field.grid(row=1, column=1, padx=(t.sp("sm"), 0))
        self.server_box.columnconfigure(0, weight=1)
        self._fields["port"] = port_field
        port_err = tk.Label(self.server_box, text="", background=t.bg_panel,
                            foreground=t.danger, font=t.font("caption_bold"), anchor="w")
        port_err._hint = None
        self._field_errors["port"] = port_err
        self.server_box.grid_remove()
        self._login_row += 1
        self._refresh_server_summary()
        for var in (self.host_var, self.port_var):
            var.trace_add("write", lambda *_a: self._refresh_server_summary())

        # Enter: move to the next empty field, or submit when everything is filled in.
        order = [self._fields[k].entry for k in ("username", "peer", "password")]
        for entry in order:
            entry.bind("<Return>", lambda _e, cur=entry: self._on_login_enter(cur, order))
        self.after(100, order[0].focus_set)

        button_frame = tk.Frame(card, background=t.bg_panel)
        button_frame.grid(row=self._login_row, column=0, sticky="ew", pady=(t.sp("md"), 0))
        self.register_button = ttk.Button(button_frame, text="Register", style="Secondary.TButton",
                                           command=lambda: self._start_auth("register"))
        self.register_button.pack(side="left", expand=True, fill="x", padx=(0, t.sp("xs")))
        self.login_button = ttk.Button(button_frame, text="Login",
                                        command=lambda: self._start_auth("login"))
        self.login_button.pack(side="left", expand=True, fill="x", padx=(t.sp("xs"), 0))
        self._login_row += 1
        first_time = tk.Label(card, text="First time? Register once; after that, Login.",
                              background=t.bg_panel, foreground=t.fg_hint, font=t.font("caption"))
        first_time.grid(row=self._login_row, column=0, sticky="w", pady=(t.sp("xs"), 0))
        self._form_groups += [button_frame, first_time]
        self._login_row += 1

        # Step-by-step progress, ticked off as the REAL connection steps complete.
        self.steps = widgets.StepList(card, t)
        self.steps.grid(row=self._login_row, column=0, sticky="ew", pady=(t.sp("md"), 0))
        self.steps.grid_remove()
        self._login_row += 1
        self.back_button = ttk.Button(card, text="Back", style="Secondary.TButton",
                                      command=self._login_back)
        self.back_button.grid(row=self._login_row, column=0, sticky="e", pady=(t.sp("sm"), 0))
        self.back_button.grid_remove()
        self._login_row += 1

    # -- login form behaviour -------------------------------------------------------

    def _toggle_password(self):
        entry = self._fields["password"].entry
        hidden = entry.cget("show") != ""
        entry.config(show="" if hidden else "•")
        self._pw_toggle.config(text="Hide" if hidden else "Show")

    def _refresh_server_summary(self):
        arrow = "▾" if self._server_open else "▸"
        self.server_toggle.config(
            text=f"{arrow} Server: {self.host_var.get().strip() or DEFAULT_HOST}:"
                 f"{self.port_var.get().strip() or DEFAULT_PORT}")

    def _toggle_server_settings(self, open_=None):
        self._server_open = (not self._server_open) if open_ is None else open_
        (self.server_box.grid if self._server_open else self.server_box.grid_remove)()
        self._refresh_server_summary()

    def _on_login_enter(self, current, order):
        empty = [e for e in order if not e.get()]
        if current is order[-1] or not empty:
            self._start_auth("login")
        else:
            empty[0].focus_set()
        return "break"

    def _show_field_errors(self, errors):
        for key, label in self._field_errors.items():
            msg = errors.get(key)
            self._fields[key].set_error(bool(msg))
            hint = getattr(label, "_hint", None)
            if msg:
                label.config(text=msg)
                if hint is not None:
                    hint.pack_forget()
                    label.pack(side="right")
                else:
                    label.grid(row=2, column=0, columnspan=2, sticky="w")
            else:
                if hint is not None:
                    label.pack_forget()
                    hint.pack(side="right")
                else:
                    label.grid_remove()
        if "port" in errors:
            self._toggle_server_settings(True)

    def _set_login_busy(self, busy):
        """While connecting, show only the brand and the progress list (the form is
        hidden, so the card always fits, even in a short window)."""
        for widget in self._form_groups:
            (widget.grid_remove if busy else widget.grid)()
        if busy:
            self.server_box.grid_remove()
            self.steps.grid()
        else:
            self._toggle_server_settings(self._server_open)
            self.steps.grid_remove()
            self.back_button.grid_remove()

    def _login_back(self):
        self._set_login_busy(False)
        self.register_button.config(state="normal")
        self.login_button.config(state="normal")
        self._fields["password"].entry.focus_set()

    def _set_login_status(self, text, error=False):
        """Compatibility shim: show a one-off message as a failed/neutral progress line."""
        self.steps.set_steps([text])
        self.steps.grid()
        self.steps.set(0, "error" if error else "active")

    def _build_chat_screen(self):
        t = self.theme
        frame = tk.Frame(self, background=t.bg_app)
        self.chat_frame = frame
        self._items = []             # everything shown in the conversation (re-rendered on rescale)
        self._wrappables = []        # (label, margin): re-wrapped when the pane is resized
        self._last_date = None
        self._session_ready = False
        self._network_visible = True
        self._tls_text = "TLS 1.3"
        self._peer_fingerprint = None

        # -- header: avatar + names + actions, then the status chips -----------------
        header = tk.Frame(frame, background=t.bg_panel, padx=t.sp("lg"), pady=t.sp("md"))
        header.pack(side="top", fill="x")
        self.header_frame = header
        self.header_row1 = row1 = tk.Frame(header, background=t.bg_panel)
        row1.pack(side="top", fill="x")
        self.header_var = tk.StringVar(value="")
        # Actions, packed FIRST (right-to-left): Tk gives space in packing order, so a long
        # name can never squeeze them out of the header. The Attack Lab button is only enabled once the
        # connected server reports lab_mode (see _apply_auth_success): a server not started
        # with --lab rejects lab_control anyway, so disabling it is the honest UI.
        self.lab_button = ttk.Button(row1, text="Attack Lab", style="Lab.TButton",
                                     command=self._open_attack_lab, state="disabled")
        self.export_button = ttk.Button(row1, text="Export Evidence", style="Secondary.TButton",
                                        command=self._on_export_evidence)
        self.network_button = ttk.Button(row1, text="Network", style="Ghost.TButton",
                                         command=self._toggle_network)
        for button in (self.lab_button, self.export_button, self.network_button):
            button.pack(side="right", padx=(t.sp("sm"), 0))

        self.avatar = widgets.Avatar(row1, t, "?", size=t.sp(44))
        self.avatar.pack(side="left", padx=(0, t.sp("md")))
        ident = tk.Frame(row1, background=t.bg_panel)
        ident.pack(side="left")
        self.peer_label = tk.Label(ident, text="", background=t.bg_panel,
                                   foreground=t.fg_primary, font=t.font("heading"), anchor="w")
        self.peer_label.pack(anchor="w")
        sub = tk.Frame(ident, background=t.bg_panel)
        sub.pack(anchor="w")
        self.me_label = tk.Label(sub, text="", background=t.bg_panel, foreground=t.fg_secondary,
                                 font=t.font("caption"))
        self.me_label.pack(side="left")
        self.session_status = tk.Label(sub, text="", background=t.bg_panel,
                                       font=t.font("caption_bold"))
        self.session_status.pack(side="left", padx=(t.sp("sm"), 0))
        self._status_hidden = False
        row1.bind("<Configure>", lambda _e: self._fit_header())

        self.chip_row = self.fp_strip = chips = tk.Frame(header, background=t.bg_panel)
        chips.pack(side="top", fill="x", pady=(t.sp("md"), 0))
        self.chip_tls = widgets.Chip(chips, t, "TLS 1.3", "off")
        self.chip_e2e = widgets.Chip(chips, t, "End-to-end encrypted", "off")
        self.chip_signed = widgets.Chip(chips, t, "Signed", "off")
        self.fp_chip = self.fp_label = widgets.Chip(chips, t, "Fingerprint pending", "warn",
                                                    mono=True, command=self._copy_fingerprint)
        for chip in (self.chip_tls, self.chip_e2e, self.chip_signed, self.fp_chip):
            chip.pack(side="left", padx=(0, t.sp("sm")))

        # -- input row (packed BEFORE the expanding pane: Tk gives space in packing order,
        # so packing it afterwards let the pane take everything and clip the message box
        # and Send button whenever the window was short) -------------------------------
        entry_frame = tk.Frame(frame, background=t.bg_app)
        entry_frame.pack(side="bottom", fill="x", padx=t.sp("lg"), pady=(0, t.sp("md")))
        self.entry_frame = entry_frame
        self.send_button = ttk.Button(entry_frame, text="Send", command=self._on_send,
                                      state="disabled")
        self.send_button.pack(side="right", padx=(t.sp("sm"), 0), fill="y")
        self.message_entry = widgets.PlaceholderText(
            entry_frame, t, placeholder="Waiting for the secure session...", max_lines=4)
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<<Send>>", lambda _e: self._on_send())
        self.message_entry.bind("<KeyRelease>", lambda _e: self._update_send_state(), add="+")

        # -- body: conversation (left) / network view (right) -------------------------
        paned = ttk.Panedwindow(frame, orient="horizontal")
        paned.pack(side="top", fill="both", expand=True, padx=t.sp("md"), pady=t.sp("md"))
        self.paned = paned

        chat_pane = tk.Frame(paned, background=t.bg_panel)
        chat_head = tk.Frame(chat_pane, background=t.bg_panel)
        chat_head.pack(side="top", fill="x", padx=t.sp("md"), pady=(t.sp("sm"), t.sp("xs")))
        tk.Label(chat_head, text="Conversation", background=t.bg_panel,
                 foreground=t.fg_secondary, font=t.font("body_bold")).pack(side="left")
        tk.Label(chat_head, text="click a message for its security receipt",
                 background=t.bg_panel, foreground=t.fg_hint,
                 font=t.font("caption")).pack(side="right")
        self._build_bubble_panel(chat_pane)
        paned.add(chat_pane, weight=3)
        self.chat_pane = chat_pane

        wire_pane = tk.Frame(paned, background=t.bg_panel_alt)
        wire_head = tk.Frame(wire_pane, background=t.bg_panel_alt)
        wire_head.pack(side="top", fill="x", padx=t.sp("md"), pady=(t.sp("sm"), t.sp("xs")))
        tk.Label(wire_head, text="Network view", background=t.bg_panel_alt,
                 foreground=t.fg_secondary, font=t.font("body_bold")).pack(side="left")
        for label, color in (("ALERT", t.wire_alert), ("CHAT", t.wire_chat),
                             ("HANDSHAKE", t.wire_handshake), ("TLS", t.wire_tls)):
            tk.Label(wire_head, text=label, background=t.bg_panel_alt, foreground=color,
                     font=t.font("mono_small_bold")).pack(side="right", padx=(t.sp("sm"), 0))
        tk.Label(wire_pane, text="what actually crosses the network (values shortened)",
                 background=t.bg_panel_alt, foreground=t.fg_hint, font=t.font("caption"),
                 anchor="w").pack(side="top", fill="x", padx=t.sp("md"))
        # width=40 keeps the Text's *requested* width small, so the Panedwindow's weights
        # (not this widget's 80-char default) decide how the width is split.
        self.wire_text = tk.Text(wire_pane, wrap="word", state="disabled", width=40,
                                 font=t.font("mono_small"), background=t.bg_panel_alt,
                                 foreground=t.fg_secondary, insertbackground=t.fg_primary,
                                 borderwidth=0, highlightthickness=0, padx=t.sp("md"),
                                 pady=t.sp("sm"), spacing1=2, spacing3=2)
        wire_scroll = ttk.Scrollbar(wire_pane, orient="vertical", command=self.wire_text.yview)
        self.wire_text.configure(yscrollcommand=wire_scroll.set)
        wire_scroll.pack(side="right", fill="y", pady=(0, t.sp("sm")))
        self.wire_text.pack(side="left", fill="both", expand=True, pady=(0, t.sp("sm")))
        self.wire_text.tag_config("ts", foreground=t.fg_hint)
        for kind, color in WIRE_COLORS(t).items():
            self.wire_text.tag_config(f"badge_{kind}", foreground=color, font=t.font("mono_small_bold"))
            self.wire_text.tag_config(f"body_{kind}", foreground=color if kind == "ALERT"
                                      else t.fg_secondary)
        paned.add(wire_pane, weight=2)
        self.wire_pane = wire_pane

    # -- header state -----------------------------------------------------------------

    def _set_session_state(self, state, peer, detail=""):
        """Header status + chips. `state` is "pending" (amber), "secure" (green) or
        "error" (red, shows `detail`)."""
        t = self.theme
        if state == "pending":
            self.session_status.config(text=f"·  ● Waiting for {peer} to come online...",
                                       foreground=t.warning)
            for chip in (self.chip_tls, self.chip_e2e, self.chip_signed):
                chip.set("off")
            self.chip_tls.set("off", self._tls_text)
            self.fp_chip.set("warn", "Fingerprint pending")
        elif state == "secure":
            self.session_status.config(text="·  ● Secure session established", foreground=t.success)
            self.chip_tls.set("ok", self._tls_text)
            self.chip_e2e.set("ok")
            self.chip_signed.set("ok")
            self.fp_chip.set("info", self._fingerprint_chip_text())
        else:
            self.session_status.config(text=f"·  ● {detail}", foreground=t.danger)
            for chip in (self.chip_e2e, self.chip_signed):
                chip.set("bad")
        self._update_send_state()

    def _fit_header(self):
        """On a narrow window drop the long status sentence (the chips already show the
        state) rather than letting the action buttons be squeezed out of the header."""
        row = self.header_row1
        avail = row.winfo_width()
        if avail <= 1:
            return
        status_w = self.session_status.winfo_reqwidth() + self.theme.sp("sm")
        if self._status_hidden:
            if avail >= row.winfo_reqwidth() + status_w + self.theme.sp("lg"):
                self.session_status.pack(side="left", padx=(self.theme.sp("sm"), 0))
                self._status_hidden = False
        elif avail < row.winfo_reqwidth():
            self.session_status.pack_forget()
            self._status_hidden = True

    def _fingerprint_chip_text(self):
        return f"Key  {self._peer_fingerprint}  ⧉" if self._peer_fingerprint \
            else "Fingerprint pending"

    def _copy_fingerprint(self):
        if not self._peer_fingerprint:
            return
        widgets.copy_to_clipboard(self, self._peer_fingerprint)
        self.fp_chip.set("ok", "Copied to clipboard ✓")
        self.after(1400, lambda: self.fp_chip.set("info", self._fingerprint_chip_text()))

    def _toggle_network(self, show=None):
        show = (not self._network_visible) if show is None else show
        if show == self._network_visible:
            return
        self._network_visible = show
        if show:
            self.paned.add(self.wire_pane, weight=2)
            self.update_idletasks()
            self.paned.sashpos(0, int(self.paned.winfo_width() * 0.58))
        else:
            self.paned.forget(self.wire_pane)
        self.network_button.config(style="Ghost.TButton" if show else "Secondary.TButton")
        self._rerender_items()   # the conversation just got wider/narrower

    def _update_send_state(self):
        ready = self._session_ready and bool(self.message_entry.get_text().strip())
        self.send_button.config(state="normal" if ready else "disabled")

    # --- conversation panel ---------------------------------------------------------------
    #
    # Each message is drawn on a small Canvas (rounded rectangle, name, text, time and a
    # shield), packed into a scrollable frame. Tkinter's native widgets have no
    # border-radius, but Canvas.create_polygon(smooth=True) over a rounded-rectangle path
    # gives genuinely curved corners for little code. Everything shown is kept in
    # self._items, so the whole conversation can be re-drawn (Presentation mode, network
    # view toggle) without losing anything.

    def _build_bubble_panel(self, parent):
        t = self.theme
        container = tk.Frame(parent, background=t.bg_panel)
        container.pack(side="top", fill="both", expand=True, padx=(t.sp("xs"), 0),
                       pady=(0, t.sp("xs")))
        # width=360: a small requested width so the Panedwindow weights decide the split.
        self.bubble_canvas = tk.Canvas(container, background=t.bg_panel, width=360,
                                       borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.bubble_canvas.yview)
        self.bubble_list = tk.Frame(self.bubble_canvas, background=t.bg_panel)
        self.bubble_list.bind(
            "<Configure>",
            lambda _e: self.bubble_canvas.configure(scrollregion=self.bubble_canvas.bbox("all")))
        self._bubble_window = self.bubble_canvas.create_window(
            (0, 0), window=self.bubble_list, anchor="nw")
        self.bubble_canvas.bind("<Configure>", self._on_bubble_canvas_resize)
        self.bubble_canvas.configure(yscrollcommand=scrollbar.set)
        self.bubble_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_bubble_canvas_resize(self, event):
        # Keep the inner frame as wide as the canvas so rows (and left/right alignment)
        # resize correctly, and re-wrap notices/cards so they are never clipped.
        self.bubble_canvas.itemconfigure(self._bubble_window, width=event.width)
        for label, margin in self._wrappables:
            label.config(wraplength=max(event.width - margin, 120))

    def _on_mousewheel(self, event):
        """Scroll the conversation only when the pointer is over it (the network view's
        Text widget scrolls itself). Windows reports deltas in steps of 120; macOS reports
        small raw deltas, so take the sign, and the step count when available."""
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None and widget is not self.bubble_canvas:
            widget = widget.master
        if widget is None or event.delta == 0:
            return
        units = max(1, abs(event.delta) // 120)
        self.bubble_canvas.yview_scroll(-units if event.delta > 0 else units, "units")

    @staticmethod
    def _rounded_rect_points(x1, y1, x2, y2, r):
        return widgets.rounded_rect_points(x1, y1, x2, y2, r)

    @staticmethod
    def _date_label(ts):
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        today = time.strftime("%Y-%m-%d")
        yesterday = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
        if day == today:
            return "Today"
        if day == yesterday:
            return "Yesterday"
        return time.strftime("%a %d %b %Y", time.localtime(ts))

    def _add_item(self, item):
        self._items.append(item)
        self._render_item(item)

    def _rerender_items(self):
        for child in self.bubble_list.winfo_children():
            child.destroy()
        self._wrappables = []
        self.update_idletasks()
        for item in self._items:
            self._render_item(item, scroll=False)
        self._scroll_bubbles_to_bottom()

    def _render_item(self, item, scroll=True):
        getattr(self, "_draw_" + item["kind"])(item)
        if scroll:
            self._scroll_bubbles_to_bottom()

    def _add_message(self, text, align, name, ts, receipt=None, gap=False):
        """align: 'e' (right, our own messages) or 'w' (left, the peer's)."""
        ts = float(ts or time.time())
        label = self._date_label(ts)
        if label != self._last_date:
            self._last_date = label
            self._add_item({"kind": "date", "text": label})
        self._add_item({"kind": "bubble", "align": align, "name": name, "text": text,
                        "ts": ts, "receipt": receipt, "gap": gap})

    def _add_bubble(self, text, align, bg, fg, timestamp_str, sender=None, receipt=None):
        """Compatibility wrapper (older call sites): colours now come from the theme."""
        self._add_message(text, align, sender or self.username or "?", time.time(), receipt)

    def _add_system_notice(self, text, warning=False):
        """System messages are centred and muted, deliberately NOT styled as a chat turn."""
        self._add_item({"kind": "notice", "text": text, "warning": warning})

    def _add_blocked_card(self, info, sender=None, ts=None):
        self._add_item({"kind": "blocked", "info": info, "sender": sender,
                        "ts": ts or time.time()})

    def _draw_date(self, item):
        t = self.theme
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=(t.sp("md"), t.sp("xs")))
        tk.Label(row, text=item["text"], background=t.bg_raised, foreground=t.fg_secondary,
                 font=t.font("caption_bold"), padx=t.sp("md"), pady=2).pack()

    def _draw_notice(self, item):
        t = self.theme
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=t.sp("sm"), padx=t.sp("md"))
        warning = item["warning"]
        wrap = max(self.bubble_canvas.winfo_width() - 40, 120)
        label = tk.Label(row, text=item["text"], background=t.bg_panel,
                         foreground=t.danger if warning else t.fg_secondary,
                         font=t.font("caption_bold" if warning else "caption"),
                         wraplength=wrap, justify="center")
        label.pack(anchor="center")
        self._wrappables.append((label, 40))

    def _draw_blocked(self, item):
        """A distinct card for something a real check blocked or flagged: what happened
        (plain English), and which defence caught it."""
        t = self.theme
        info = item["info"]
        bad = info["severity"] == "bad"
        color, bg = (t.danger, t.bg_danger_soft) if bad else (t.warning, t.bg_warning_soft)
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=t.sp("sm"), padx=t.sp("md"))
        card = tk.Frame(row, background=bg, highlightbackground=color, highlightcolor=color,
                        highlightthickness=1)
        card.pack(fill="x")
        tk.Frame(card, background=color, width=t.sp(4)).pack(side="left", fill="y")
        body = tk.Frame(card, background=bg, padx=t.sp("md"), pady=t.sp("sm"))
        body.pack(side="left", fill="x", expand=True)

        head = tk.Frame(body, background=bg)
        head.pack(fill="x")
        size = t.sp(22)
        badge = tk.Canvas(head, width=size, height=size, background=bg, highlightthickness=0)
        badge.create_oval(1, 1, size - 1, size - 1, fill=color, outline="")
        badge.create_text(size / 2, size / 2, text="✕" if bad else "!", fill="#1a0b0b",
                          font=t.font("caption_bold"))
        badge.pack(side="left", padx=(0, t.sp("sm")))
        tk.Label(head, text=info["headline"], background=bg, foreground=color,
                 font=t.font("body_bold"), anchor="w").pack(side="left", fill="x")
        if item.get("sender"):
            tk.Label(head, text=time.strftime("%H:%M", time.localtime(item["ts"])),
                     background=bg, foreground=t.fg_secondary,
                     font=t.font("caption")).pack(side="right")

        explain = tk.Label(body, text=info["explain"], background=bg, foreground=t.fg_primary,
                           font=t.font("body"), justify="left", anchor="w")
        explain.pack(fill="x", pady=(t.sp("xs"), t.sp("xs")))
        self._wrappables.append((explain, 90))
        caught = tk.Frame(body, background=bg)
        caught.pack(fill="x")
        tk.Label(caught, text="Caught by", background=bg, foreground=t.fg_secondary,
                 font=t.font("caption")).pack(side="left", padx=(0, t.sp("sm")))
        widgets.Chip(caught, t, info["check"], "bad_dark" if bad else "warn_dark").pack(side="left")
        if info.get("detail"):
            detail = tk.Label(body, text=str(info["detail"]), background=bg,
                              foreground=t.fg_hint, font=t.font("mono_small"),
                              justify="left", anchor="w")
            detail.pack(fill="x", pady=(t.sp("xs"), 0))
            self._wrappables.append((detail, 90))
        w = self.bubble_canvas.winfo_width()
        for label, margin in self._wrappables[-2:]:
            label.config(wraplength=max(w - margin, 120))

    def _draw_bubble(self, item):
        t = self.theme
        own = item["align"] == "e"
        gap = item["gap"]
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=t.sp("xs"), padx=t.sp("md"))
        avatar_size = t.sp(32)
        widgets.Avatar(row, t, item["name"], size=avatar_size).pack(
            side="right" if own else "left", anchor="n",
            padx=(t.sp("sm"), 0) if own else (0, t.sp("sm")))

        pad_x, pad_y, line_gap = t.sp("md"), t.sp("sm"), t.sp("xs")
        pane_w = max(self.bubble_canvas.winfo_width(), 320)
        max_text = max(150, min(460, int(pane_w * 0.78) - avatar_size - t.sp("sm") - pad_x * 2
                                - t.sp("md") * 2))
        fonts = {"body": t.font("body"), "name": t.font("caption_bold"), "time": t.font("caption")}
        bg = t.bg_bubble_sent if own else t.bg_bubble_recv
        fg = t.fg_on_sent if own else t.fg_on_recv
        name_fg = t.fg_on_sent if own else t.accent
        meta_fg = t.fg_on_sent if own else t.fg_secondary
        name = "You" if own else item["name"]
        stamp = time.strftime("%H:%M", time.localtime(item["ts"]))

        canvas = tk.Canvas(row, background=t.bg_panel, borderwidth=0, highlightthickness=0)

        def measure(**kw):
            probe = canvas.create_text(0, 0, anchor="nw", **kw)
            x1, y1, x2, y2 = canvas.bbox(probe)
            canvas.delete(probe)
            return x2 - x1, y2 - y1

        text_w, text_h = measure(text=item["text"], font=fonts["body"], width=max_text)
        name_w, name_h = measure(text=name, font=fonts["name"])
        time_w, time_h = measure(text=stamp, font=fonts["time"])
        shield = t.sp(14) if item["receipt"] else 0
        meta_w = time_w + (shield + t.sp("xs") if shield else 0)
        bubble_w = max(text_w, name_w, meta_w) + pad_x * 2
        bubble_h = pad_y + name_h + line_gap + text_h + line_gap + time_h + pad_y
        canvas.configure(width=bubble_w, height=bubble_h)

        canvas.create_polygon(self._rounded_rect_points(1, 1, bubble_w - 1, bubble_h - 1, 14),
                              smooth=True, fill=bg, outline=bg)
        canvas.create_text(pad_x, pad_y, text=name, font=fonts["name"], fill=name_fg, anchor="nw")
        canvas.create_text(pad_x, pad_y + name_h + line_gap, text=item["text"],
                           font=fonts["body"], fill=fg, width=max_text, anchor="nw")
        meta_y = bubble_h - pad_y
        right = bubble_w - pad_x
        if shield:
            # A shield on every message that passed ALL the client's checks (a gap in the
            # hash chain is shown amber with "!": the message is authentic but flagged).
            sx, sy = right - shield / 2, meta_y - time_h / 2
            fill = (t.warning if gap else ("#d1fae5" if own else t.success))
            widgets.draw_shield(canvas, sx, sy, shield, fill=fill)
            if gap:
                canvas.create_text(sx, sy, text="!", fill="#2b1d00", font=fonts["name"])
            else:
                widgets.draw_check(canvas, sx, sy + 1, shield * 0.8,
                                   "#065f46" if own else "#052e16", width=2)
            right -= shield + t.sp("xs")
        canvas.create_text(right, meta_y, text=stamp, font=fonts["time"], fill=meta_fg, anchor="se")

        if item["receipt"]:
            # Clicking a bubble opens its security receipt.
            canvas.configure(cursor="pointinghand" if sys.platform == "darwin" else "hand2")
            canvas.bind("<Button-1>", lambda _e, r=item["receipt"]: self._show_receipt(r))
        canvas.pack(side="right" if own else "left")

    def _scroll_bubbles_to_bottom(self):
        self.bubble_list.update_idletasks()
        self.bubble_canvas.configure(scrollregion=self.bubble_canvas.bbox("all"))
        self.bubble_canvas.yview_moveto(1.0)

    def _show_login_screen(self):
        self._chat_ready = False
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def _show_chat_screen(self):
        self._chat_ready = True
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        # Lay the chat screen out now, so the first notices/bubbles are sized against the
        # real pane width rather than an unmapped 1px one. ttk.Panedwindow only applies
        # pane weights on *resize*; the initial split comes from requested widths, so set
        # the divider explicitly. A narrow window starts with the network view hidden
        # (the conversation needs the room); the header button brings it back.
        self.update_idletasks()
        if self._network_visible and self.winfo_width() < NETWORK_MIN_WIDTH:
            self._toggle_network(False)
        elif self._network_visible:
            self.paned.sashpos(0, int(self.paned.winfo_width() * 0.58))
        self.update_idletasks()
        self.message_entry.focus_set()

    # --- login / register (background thread) --------------------------

    def _start_auth(self, mode):
        if str(self.register_button.cget("state")) == "disabled":
            return  # an attempt is already in flight (e.g. Enter pressed twice)
        host = self.host_var.get().strip() or DEFAULT_HOST
        errors = validate_login_form(host, self.port_var.get(), self.username_var.get(),
                                     self.peer_var.get(), self.password_var.get())
        self._show_field_errors(errors)
        if errors:
            return
        port = int(self.port_var.get().strip() or DEFAULT_PORT)
        username = self.username_var.get().strip()
        peer = self.peer_var.get().strip()
        password = self.password_var.get()

        self._login_mode = mode
        self._holding, self._held_events, self._auth_data = False, [], None
        self._handshake_done, self._tls_fingerprint = False, None
        self.register_button.config(state="disabled")
        self.login_button.config(state="disabled")
        self.steps.set_steps([
            "Connecting over TLS 1.3",
            "Verifying the server certificate",
            "Registering your account" if mode == "register" else "Logging in",
            f"Exchanging keys with {peer}",
            "Verifying the handshake signature",
        ])
        self._set_login_busy(True)
        self.steps.set(0, "active")

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
            sock = connect_tls(
                host, port,
                on_cert_fingerprint=lambda fp: self.event_queue.put(
                    ("tls_cert_fingerprint", {"fingerprint": fp})
                ),
            )
        except TLSSetupError as exc:
            self.event_queue.put(("auth_error", {"detail": str(exc), "stage": "tls"}))
            return
        # connect_tls only returns once the TLS handshake AND the certificate check
        # succeeded; the negotiated protocol version is read straight off the socket.
        try:
            tls_version = sock.version()
        except (AttributeError, OSError, ValueError):
            tls_version = None
        self.event_queue.put(("tls_connected", {"version": tls_version}))

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
            self.event_queue.put(("auth_error", {"detail": reason, "stage": "auth"}))
            try:
                sock.close()
            except OSError:
                pass
            return

        client.lab_mode = bool(result.get("lab_mode"))

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
            "username": username, "peer": peer, "lab_mode": client.lab_mode,
            "own_fingerprint": own_fingerprint, "peer_key_found": peer_key_found,
        }))

    # --- login progress (ticked off by real events) ----------------------------------

    def _login_step_event(self, kind, data):
        """Update the progress list from a REAL event. Safe to call in any order: the
        handshake can finish before auth_success is processed on the receiving side."""
        s = self.steps
        if kind == "tls_cert_fingerprint":
            self._tls_fingerprint = data["fingerprint"]
        elif kind == "tls_connected":
            version = (data.get("version") or "TLSv1.3").replace("TLSv", "TLS ")
            s.set(0, "done", f"Connected over {version}")
            fp = self._tls_fingerprint
            s.set(1, "done", "Server certificate verified"
                  + (f" (fingerprint {fp})" if fp else ""))
            s.set(2, "active")
        elif kind == "auth_success":
            who = data["username"]
            s.set(2, "done", f"{'Registered' if self._login_mode == 'register' else 'Logged in'} as {who}")
            if self._handshake_done:
                return
            if data.get("peer_key_found"):
                s.set(3, "active")
            else:
                s.set(3, "waiting", f"Waiting for {data['peer']} to come online")
        elif kind in ("handshake_started", "handshake_waiting"):
            if s.state(2) == "done" and s.state(3) != "done":
                s.set(3, "active")
        elif kind == "handshake_established":
            self._handshake_done = True
            s.set(2, "done") if s.state(2) != "done" else None
            s.set(3, "done", f"Keys exchanged with {data['peer']}")
            s.set(4, "done")

    def _login_failed(self, data):
        detail = data.get("detail")
        step = 0 if data.get("stage") == "tls" else 2
        self.steps.grid()
        self.steps.set(step, "error", f"{self.steps._rows[step][2].cget('text')}: {detail}")
        self.back_button.grid()      # the form stays hidden; Back restores it for another try

    def _login_progress(self, kind, data):
        """Map a (possibly early) real event onto the progress list."""
        if kind == "envelope_received" and data["envelope"].get("type") in (
                "handshake_init", "handshake_response"):
            kind, data = "handshake_started", {"peer": self.peer}
        if kind in LOGIN_STEP_KINDS:
            self._login_step_event(kind, data)

    def _handoff_to_chat(self):
        """Leave the login screen once the progress list has had a moment to finish."""
        if not self._holding:
            return
        self._holding = False
        data, held = self._auth_data, self._held_events
        self._auth_data, self._held_events = None, []
        self._apply_auth_success(data)
        for kind, payload in held:       # replay what arrived meanwhile, in order
            self._handle_event(kind, payload)

    def _apply_auth_success(self, data):
        pair = f"{data['username']}  ↔  {data['peer']}"
        self.header_var.set(pair)
        self.title(f"Secure Chat (GUI) — {pair}")
        self.peer_label.config(text=data["peer"])
        self.me_label.config(text=f"You: {data['username']}")
        self.avatar.set_name(data["peer"])
        self._set_session_state("pending", data["peer"])
        self._show_chat_screen()
        if data.get("own_fingerprint"):
            self._add_system_notice(f"Your key fingerprint: {data['own_fingerprint']}")
        if not data.get("peer_key_found"):
            # Normal when this side logs in first: the key is fetched again automatically
            # once the peer joins and starts the handshake (see "handshake_waiting").
            self._add_system_notice(
                f"{data['peer']} isn't registered or online yet -- the secure "
                f"session will start automatically when they log in.")
        if data.get("lab_mode"):
            self.lab_button.config(state="normal")

    # --- per-message security receipt (Stage E) -------------------------------
    #
    # Pure presentation: every value shown was already verified by
    # SecureChatClient before the message was displayed; the client attaches
    # them to the message_sent / message_received event as `receipt`.

    def _show_receipt(self, receipt):
        t = self.theme
        win = tk.Toplevel(self)
        win.title("Security receipt")
        win.configure(background=t.bg_panel)
        win.resizable(False, False)
        win.transient(self)
        win.bind("<Escape>", lambda _e: win.destroy())

        body = tk.Frame(win, background=t.bg_panel, padx=22, pady=18)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)

        def short(value, n=20):
            return "-" if not value else (value if len(value) <= n else value[:n] + "…")

        sent = receipt.get("direction") == "sent"
        tk.Label(body, text="Security receipt", background=t.bg_panel,
                 foreground=t.fg_primary,
                 font=(t.ui_font, t.size(14), "bold")).grid(row=0, column=0, columnspan=2,
                                                            sticky="w")
        tk.Label(body, text=("Message you sent" if sent else "Message you received"),
                 background=t.bg_panel, foreground=t.fg_secondary,
                 font=(t.ui_font, t.size(9))).grid(row=1, column=0, columnspan=2,
                                                   sticky="w", pady=(0, 14))

        # (label, value, color, monospace)
        sender_text = f"{receipt.get('sender')}  ({receipt.get('sender_fingerprint') or 'no fingerprint'})"
        rows = [("Sender", sender_text, t.fg_primary, False)]
        if sent:
            rows.append(("Signature", "✔ signed with your private key (RSA-PSS / SHA-256)",
                         t.fg_accent, False))
            rows.append(("Encryption", "✔ AES-256-GCM, fresh nonce per message",
                         t.fg_accent, False))
            rows.append(("Sent at", time.strftime("%H:%M:%S", time.localtime(
                receipt.get("timestamp", 0))), t.fg_primary, False))
            rows.append(("Chain position", f"seq #{receipt.get('seq')}  (your direction)",
                         t.fg_primary, False))
            rows.append(("prev_hash (signed)", short(receipt.get("prev_hash")), t.fg_primary, True))
        else:
            rows.append(("AES-GCM tag", "✔ verified (not tampered with in transit)",
                         t.fg_accent, False))
            rows.append(("RSA signature", "✔ verified against the sender's public key",
                         t.fg_accent, False))
            rows.append(("Timestamp", f"✔ fresh  ({receipt.get('age_seconds', 0)} s old when received)",
                         t.fg_accent, False))
            if receipt.get("chain_link") == "gap":
                rows.append(("Chain position", f"seq #{receipt.get('seq')}  ⚠ earlier message(s) "
                             f"missing before this one", t.fg_warning, False))
            else:
                rows.append(("Chain position", f"seq #{receipt.get('seq')}  ✔ links to the "
                             f"previous message", t.fg_accent, False))
            rows.append(("prev_hash", short(receipt.get("prev_hash")), t.fg_primary, True))
        rows.append(("Nonce", short(receipt.get("nonce")), t.fg_primary, True))
        rows.append(("Record SHA-256", short(receipt.get("record_hash")), t.fg_primary, True))

        for i, (label, value, color, mono) in enumerate(rows, start=2):
            tk.Label(body, text=label, background=t.bg_panel, foreground=t.fg_secondary,
                     font=(t.ui_font, t.size(10)), anchor="w").grid(
                row=i, column=0, sticky="nw", padx=(0, 18), pady=3)
            tk.Label(body, text=value, background=t.bg_panel, foreground=color,
                     font=(t.mono_font if mono else t.ui_font, t.size(10)),
                     anchor="w", justify="left", wraplength=360).grid(
                row=i, column=1, sticky="w", pady=3)

        ttk.Button(body, text="Close", command=win.destroy).grid(
            row=len(rows) + 2, column=0, columnspan=2, sticky="e", pady=(16, 0))

        win.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + 80
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        return win

    # --- Attack Lab (Stage C) --------------------------------------------------
    #
    # Opt-in, lab-mode-only, and enforced entirely server-side (see
    # server/server.py's ChatServer._handle_lab_control): this panel only
    # sends a request; the server decides whether to honor it. Detection is
    # never claimed here -- it comes from the OTHER window's own, unmodified
    # client-side checks (GCM tag, RSA signature, replay window, hash chain,
    # handshake signature), visible live in that window's Conversation/Wire
    # Log, exactly as an unprompted attack would be.

    _LAB_ACTIONS = [
        ("tamper_next", "Tamper next message",
         "The relay flips a byte of your next message's ciphertext in transit."),
        ("replay_last", "Replay last message",
         "The relay immediately resends your most recent message a second time."),
        ("drop_next", "Drop next message",
         "The relay silently discards your next message -- it never reaches your peer."),
        ("mitm_next_handshake", "MITM next handshake",
         "The relay substitutes its own key in the next ECDH handshake you start "
         "(arm this before your peer logs in, if you're the one who'll initiate)."),
    ]

    def _open_attack_lab(self):
        if self.client is None or not self.client.lab_mode:
            return
        t = self.theme
        win = tk.Toplevel(self)
        win.title("Attack Lab")
        win.configure(background=t.bg_lab_panel)
        win.resizable(False, False)
        win.transient(self)
        win.bind("<Escape>", lambda _e: win.destroy())
        self._lab_window = win

        banner = tk.Frame(win, background=t.bg_lab, padx=16, pady=10)
        banner.pack(fill="x")
        tk.Label(banner, text="LAB MODE: relay is acting maliciously on request",
                 background=t.bg_lab, foreground="#ffffff",
                 font=(t.ui_font, t.size(11), "bold")).pack(anchor="w")

        body = tk.Frame(win, background=t.bg_lab_panel, padx=18, pady=14)
        body.pack(fill="both", expand=True)
        tk.Label(body, text=f"Every action below targets YOUR OWN next outgoing message "
                             f"or handshake ({self.client.username}), relayed to "
                             f"{self.client.peer}. Each is one-shot: it fires once, then "
                             f"disarms itself.",
                 background=t.bg_lab_panel, foreground=t.fg_secondary,
                 font=(t.ui_font, t.size(9)), wraplength=420, justify="left").pack(
            anchor="w", pady=(0, 12))

        self._lab_result_var = tk.StringVar(value="No action armed yet.")
        tk.Label(body, textvariable=self._lab_result_var, background=t.bg_lab_panel,
                 foreground=t.fg_lab_banner, font=(t.mono_font, t.size(9)),
                 wraplength=420, justify="left").pack(anchor="w", pady=(0, 14))

        for action, label, desc in self._LAB_ACTIONS:
            row = tk.Frame(body, background=t.bg_lab_panel)
            row.pack(fill="x", pady=(0, 10))
            ttk.Button(row, text=label, style="Lab.TButton",
                      command=lambda a=action: self._arm_lab_action(a)).pack(anchor="w")
            tk.Label(row, text=desc, background=t.bg_lab_panel, foreground=t.fg_secondary,
                     font=(t.ui_font, t.size(9)), wraplength=420, justify="left").pack(
                anchor="w", pady=(3, 0))

        ttk.Button(body, text="Close", command=win.destroy).pack(anchor="e", pady=(4, 0))

        win.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + 60
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _arm_lab_action(self, action):
        if self.client is None:
            return
        label = next(l for a, l, _ in self._LAB_ACTIONS if a == action)
        self._lab_result_var.set(f"Arming: {label}...")
        threading.Thread(target=self.client.send_lab_control, args=(action,),
                         daemon=True).start()

    def _lab_window_alive(self):
        win = getattr(self, "_lab_window", None)
        return win is not None and win.winfo_exists()

    # --- evidence export -----------------------------------------------------

    def _on_export_evidence(self):
        if self.client is None:
            return
        try:
            path = self.client.export_evidence()
        except EvidenceError as exc:
            self._add_system_notice(f"Cannot export evidence yet: {exc}", warning=True)
            return
        except OSError as exc:
            self._add_system_notice(f"Could not write the evidence file: {exc}", warning=True)
            return
        rel = os.path.relpath(path, os.getcwd())
        self._add_system_notice(
            f"Evidence exported: {rel}\nVerify it independently with:\n"
            f"python tools/verify_transcript.py \"{rel}\"")
        self._append_wire(f"signed evidence file written: {rel}", "INFO")

    # --- sending ---------------------------------------------------------

    def _on_send(self):
        if self.client is None or not self._session_ready:
            return
        text = self.message_entry.get_text()
        if not text.strip():
            return
        self.message_entry.set_text("")
        self._update_send_state()
        threading.Thread(target=self.client.send_message, args=(text.rstrip("\n"),),
                         daemon=True).start()

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
        if kind == "tls_cert_fingerprint":
            self._append_wire(
                f"trusting server cert fingerprint: {data['fingerprint']}", "TLS")
            self._login_step_event(kind, data)
            return

        if kind == "tls_connected":
            self._tls_text = (data.get("version") or "TLSv1.3").replace("TLSv", "TLS ")
            self._login_step_event(kind, data)
            return

        if kind == "auth_error":
            self._login_failed(data)
            return

        if kind == "auth_success":
            self._login_step_event(kind, data)
            self._auth_data, self._holding = data, True
            delay = (HANDOFF_PEER_OFFLINE_MS if not data.get("peer_key_found")
                     else (900 if self._handshake_done else HANDOFF_WAIT_MS))
            self.after(delay, self._handoff_to_chat)
            return

        if not self._chat_ready:
            # Still on the login screen: the chat widgets are unmapped (and unsized), so
            # buffer chat-screen events and replay them, in order, once it is shown --
            # while keeping the progress list live from the same real events.
            self._login_progress(kind, data)
            self._held_events.append((kind, data))
            if kind == "handshake_established" and self._holding:
                self.after(700, self._handoff_to_chat)
            return

        if kind == "lab_control_result":
            if self._lab_window_alive():
                verb = "Armed" if data.get("armed") else "Rejected"
                self._lab_result_var.set(f"{verb}: {data.get('detail')}")
            return

        if kind == "lab_attack_performed":
            if self._lab_window_alive():
                self._lab_result_var.set(
                    f"Performed by relay: {data.get('detail')}\n"
                    f"(watch {self.peer}'s window for the result)")
            return

        if kind == "envelope_sent":
            self._append_wire_envelope("→", data["envelope"])
            return

        if kind == "envelope_received":
            self._append_wire_envelope("←", data["envelope"])
            return

        if kind == "handshake_started":
            self._append_wire(f"starting ECDH key exchange with {data['peer']}...", "HANDSHAKE")
            return

        if kind == "handshake_waiting":
            self._append_wire(
                f"waiting on {data['peer']}'s RSA public key to verify an incoming "
                f"handshake message...", "HANDSHAKE")
            return

        if kind == "handshake_established":
            self._append_wire(f"session key established with {data['peer']} "
                              f"(ECDH, authenticated by RSA signature)", "HANDSHAKE")
            self._add_system_notice(f"Secure session established with {data['peer']}.")
            self._session_ready = True
            self.message_entry.set_placeholder(
                "Type a message  (Enter sends, Shift+Enter for a new line)")
            self._set_session_state("secure", data["peer"])
            return

        if kind == "handshake_aborted":
            info = describe_rejection("handshake_aborted", data.get("reason"), data.get("reason"))
            self._append_wire(f"ABORTED with {data['peer']}: {data['reason']}", "ALERT")
            self._add_blocked_card(info)
            self._session_ready = False
            self.message_entry.set_placeholder("No secure session -- sending is disabled")
            self._set_session_state("error", data["peer"], "Handshake aborted -- not secure")
            return

        if kind == "peer_fingerprint":
            self._peer_fingerprint = data["fingerprint"]
            self.fp_chip.set("info" if self._session_ready else "warn",
                             self._fingerprint_chip_text())
            self._append_wire(f"{data['peer']}'s RSA key fingerprint: {data['fingerprint']}",
                              "HANDSHAKE")
            return

        if kind == "message_sent":
            self._add_message(data["message"], "e", self.username, data.get("timestamp"),
                              receipt=data.get("receipt"))
            return

        if kind == "message_queued":
            self._add_system_notice(
                f"Message queued until the secure session is ready: {data['message']}")
            return

        if kind == "message_received":
            receipt = data.get("receipt") or {}
            self._add_message(data["message"], "w", data["sender"], data.get("timestamp"),
                              receipt=data.get("receipt"), gap=receipt.get("chain_link") == "gap")
            return

        if kind in ("message_rejected", "chain_warning"):
            # Both come straight from the client's real checks. A rejected message was
            # NOT displayed; a chain warning (gap) accompanies a message that was.
            info = describe_rejection(kind, data.get("reason"), data.get("detail"))
            self._add_blocked_card(info, sender=data.get("sender"))
            self._append_wire(f"{info['headline']} (from {data.get('sender')}): "
                              f"{data.get('detail')}", "ALERT")
            return

        if kind == "system_message":
            self._add_system_notice(data["text"])
            return

        if kind == "disconnected":
            reason = data.get("reason", "")
            self._session_ready = False
            self._set_session_state("error", self.peer,
                                    f"Disconnected from server ({reason}) -- restart to reconnect")
            self._add_system_notice("Disconnected from server.", warning=True)
            self.message_entry.set_placeholder("Disconnected")
            self.send_button.config(state="disabled")
            return

    # --- network view helper ---------------------------------------------------

    def _append_wire(self, text, kind="INFO"):
        """One line in the network view: time, a coloured badge for the kind of traffic
        (TLS / HANDSHAKE / CHAT / ALERT / AUTH), then the (shortened) content."""
        kind = {"info": "INFO", "sent": "CHAT", "recv": "CHAT", "warning": "ALERT"}.get(kind, kind)
        w = self.wire_text
        w.config(state="normal")
        w.insert("end", time.strftime("%H:%M:%S") + "  ", ("ts",))
        w.insert("end", f"{kind:<9}", (f"badge_{kind}",))
        w.insert("end", f" {text}\n", (f"body_{kind}",))
        w.see("end")
        w.config(state="disabled")

    def _append_wire_envelope(self, arrow, envelope):
        text, is_warning = format_envelope_line("-->" if arrow == "→" else "<--", envelope)
        kind = "ALERT" if is_warning and wire_kind(envelope) != "AUTH" else wire_kind(envelope)
        self._append_wire(text.replace("-->", arrow, 1).replace("<--", arrow, 1), kind)

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
    import argparse
    parser = argparse.ArgumentParser(description="Secure Chat GUI client")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="server port to pre-fill on the login screen "
                             f"(default {DEFAULT_PORT})")
    parser.add_argument("--geometry", help="initial window size/position, e.g. 780x560+10+40")
    args = parser.parse_args()
    app = ChatGUI()
    app.port_var.set(str(args.port))
    if args.geometry:
        app.geometry(args.geometry)
    app.mainloop()


if __name__ == "__main__":
    main()
