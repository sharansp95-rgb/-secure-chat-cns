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
from gui.macos import set_app_name  # noqa: E402
from server.security_log import DEFAULT_LOG_PATH, read_events  # noqa: E402
from gui.explain import (  # noqa: E402
    LAB_ATTACKS,
    LAB_BY_ACTION,
    LAB_SILENT_AFTER_SECONDS,
    banner_for,
    describe_rejection,
    find_lab_detection,
    lab_status,
    receipt_details,
    receipt_rows,
    receipt_summary,
    shorten,
)
from gui.theme import Theme, hand_cursor  # noqa: E402

POLL_INTERVAL_MS = 50
LAB_POLL_MS = 600
BANNER_OK_SECONDS = 20     # "ok" banners fade after this long; warnings/blocks stay
TAGLINE = "Accountable end-to-end encrypted messaging for hospitals"
NETWORK_MIN_WIDTH = 700       # narrower windows start with the network view hidden
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

    if etype == "security_alert":
        return (f"{direction} security_alert: alert={e.get('alert')} "
                f"reason={_truncate(str(e.get('reason')), 36)} peer={e.get('peer')}"), False

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
    def __init__(self, log_path=None):
        super().__init__()
        self.log_path = log_path or DEFAULT_LOG_PATH   # read-only: Attack Lab results
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
        self._lab_state = {a['action']: {'state': 'idle', 'fired_at': 0.0, 'detail': None}
                           for a in LAB_ATTACKS}
        self._lab_last_message = 'No action armed yet.'
        self._auth_data = None       # auth_success payload, while the login screen waits
        self._held_events = []       # events that arrived during that wait (replayed in order)
        self._holding = False
        self._chat_ready = False     # the chat screen has been shown (events are applied live)
        self._handshake_done = False
        self._tls_fingerprint = None
        self._login_mode = "login"

        self.presentation_var = tk.BooleanVar(value=False)   # View menu: Presentation mode
        self._build_login_screen()
        self._build_chat_screen()
        self._build_menubar()
        widgets.install_presentation_shortcuts(self, self.toggle_presentation)
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
        self.login_logo = widgets.Logo(brand, t, size=t.sp(56))
        self.login_logo.pack(side="left", padx=(0, t.sp("md")))
        names = tk.Frame(brand, background=t.bg_panel)
        names.pack(side="left", fill="x", expand=True)
        tk.Label(names, text="Secure Chat", background=t.bg_panel, foreground=t.fg_primary,
                 font=t.font("title"), anchor="w").pack(anchor="w")
        self.tagline_label = tk.Label(names, text=TAGLINE, background=t.bg_panel,
                                      foreground=t.fg_secondary, font=t.font("caption"),
                                      wraplength=300, justify="left", anchor="w")
        self.tagline_label.pack(anchor="w")

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
                                       cursor=hand_cursor())
            self._pw_toggle.bind("<Button-1>", lambda _e: self._toggle_password())
            return self._pw_toggle
        add_field("password", "Password", self.password_var, show="•", trailing=toggle)

        # Server settings stay out of the way (they are set once by the launcher) but are
        # one click away, and open by themselves if the port is invalid.
        self._server_open = False
        self.server_toggle = tk.Label(card, text="", background=t.bg_panel, foreground=t.fg_hint,
                                      font=t.font("caption"), cursor=hand_cursor(), anchor="w")
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
        self.explain_var = tk.BooleanVar(value=True)     # settings menu: "Explain events"
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
        self.settings_button = ttk.Button(row1, text="⚙", style="Ghost.TButton", width=3,
                                          command=self._popup_settings)
        self.settings_menu = tk.Menu(self, tearoff=0)
        self.settings_menu.add_checkbutton(label="Explain events", variable=self.explain_var,
                                           command=self._on_explain_toggled)
        self.settings_menu.add_command(label="Show / hide network view",
                                       command=self._toggle_network)
        self.settings_menu.add_checkbutton(
            label=f"Presentation mode  ({widgets.presentation_accelerator()})",
            variable=self.presentation_var, command=self._on_presentation_menu)
        self.settings_button.pack(side="right", padx=(t.sp("sm"), 0))

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

        # "What just happened?" banner: sits right under the header, empty until a real
        # event of interest happens (see gui/explain.py: banner_for).
        # height=1: Tk keeps a childless frame at its LAST size, so after a banner is
        # dismissed the holder is shrunk back explicitly (see _dismiss_banner).
        self.banner_holder = tk.Frame(frame, background=t.bg_app, height=1)
        self.banner_holder.pack(side="top", fill="x")
        self._banner = None
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
        wire_head.pack(side="top", fill="x", padx=t.sp("md"), pady=(t.sp("sm"), 0))
        tk.Label(wire_head, text="Network view", background=t.bg_panel_alt,
                 foreground=t.fg_secondary, font=t.font("body_bold")).pack(side="left")
        tk.Label(wire_head, text="values shortened", background=t.bg_panel_alt,
                 foreground=t.fg_hint, font=t.font("caption")).pack(side="right")
        legend = tk.Frame(wire_pane, background=t.bg_panel_alt)
        legend.pack(side="top", fill="x", padx=t.sp("md"), pady=(0, t.sp("xs")))
        for label, color in (("TLS", t.wire_tls), ("HANDSHAKE", t.wire_handshake),
                             ("CHAT", t.wire_chat), ("ALERT", t.wire_alert)):
            tk.Label(legend, text=label, background=t.bg_panel_alt, foreground=color,
                     font=t.font("mono_small_bold")).pack(side="left", padx=(0, t.sp("sm")))
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

    def _popup_settings(self):
        button = self.settings_button
        self.settings_menu.tk_popup(button.winfo_rootx(), button.winfo_rooty() + button.winfo_height())

    # --- Presentation mode (bigger fonts and padding for a projector) ------------------------

    def _build_menubar(self):
        """A real menu-bar "View" menu, so Presentation mode is also reachable by menu."""
        menubar = tk.Menu(self)
        view = tk.Menu(menubar, tearoff=0)
        view.add_checkbutton(label="Presentation mode", accelerator=widgets.presentation_accelerator(),
                             variable=self.presentation_var, command=self._on_presentation_menu)
        view.add_checkbutton(label="Explain events", variable=self.explain_var,
                             command=self._on_explain_toggled)
        view.add_command(label="Show / hide network view", command=self._toggle_network)
        menubar.add_cascade(label="View", menu=view)
        self.config(menu=menubar)
        self.view_menu = view

    def toggle_presentation(self):
        self.set_presentation(not self.theme.presentation)

    def _on_presentation_menu(self):
        self.set_presentation(self.presentation_var.get())

    def set_presentation(self, on):
        """Switch Presentation mode: every font and every bit of padding ~25% larger (or back),
        the window grows with it (never past the screen), and the conversation is redrawn."""
        on = bool(on)
        self.presentation_var.set(on)
        if on == self.theme.presentation:
            return
        lab_was_open = self._lab_window_alive()
        for child in list(self.winfo_children()):        # Attack Lab / receipt: rebuilt on open
            if isinstance(child, tk.Toplevel):
                child.destroy()
        ratio = self.theme.set_presentation(on)
        widgets.rescale_tree(self, ratio)
        t = self.theme
        self.avatar.resize(t.sp(44))
        self.login_logo.resize(t.sp(56))
        self.tagline_label.config(wraplength=t.sp(300))
        for _frame, _glyph, label in self.steps._rows:
            label.config(wraplength=t.sp(360))
        widgets.scale_window(self, ratio)
        self.update_idletasks()
        if self._chat_ready:
            self._rerender_items()
            self._fit_header()
            if self._network_visible:
                self.paned.sashpos(0, int(self.paned.winfo_width() * 0.58))
        if lab_was_open:
            self._open_attack_lab()

    # --- "What just happened?" banner ------------------------------------------------------

    def _maybe_banner(self, kind, data):
        """Show the plain-English banner for a real event, if the user wants explanations."""
        if not self.explain_var.get():
            return
        banner = banner_for(kind, dict(data, peer=self.peer))
        if banner:
            self._show_banner(*banner)

    def _show_banner(self, severity, text):
        t = self.theme
        self._dismiss_banner()
        color = {"ok": t.success, "bad": t.danger, "warn": t.warning, "info": t.accent}[severity]
        bg = {"ok": t.bg_success_soft, "bad": t.bg_danger_soft, "warn": t.bg_warning_soft,
              "info": t.bg_accent_soft}[severity]
        banner = tk.Frame(self.banner_holder, background=bg, highlightbackground=color,
                          highlightcolor=color, highlightthickness=1)
        banner.pack(fill="x", padx=t.sp("md"), pady=(t.sp("sm"), 0))
        tk.Frame(banner, background=color, width=t.sp(4)).pack(side="left", fill="y")
        close = tk.Label(banner, text="✕", background=bg, foreground=t.fg_secondary,
                         font=t.font("body_bold"), cursor=hand_cursor(), padx=t.sp("md"))
        close.pack(side="right", anchor="n")
        close.bind("<Button-1>", lambda _e: self._dismiss_banner())
        body = tk.Frame(banner, background=bg, padx=t.sp("md"), pady=t.sp("sm"))
        body.pack(side="left", fill="x", expand=True)
        tk.Label(body, text="WHAT JUST HAPPENED", background=bg, foreground=color,
                 font=t.font("caption_bold"), anchor="w").pack(anchor="w")
        label = tk.Label(body, text=text, background=bg, foreground=t.fg_primary,
                         font=t.font("body"), justify="left", anchor="w",
                         wraplength=max(self.winfo_width() - 110, 240))
        label.pack(anchor="w", fill="x")
        self._banner = (banner, label)
        self.banner_label = label
        if severity == "ok":     # good news fades after a while; warnings stay until dismissed
            self._banner_job = self.after(BANNER_OK_SECONDS * 1000,
                                          lambda b=banner: self._dismiss_if_current(b))

    def _dismiss_banner(self):
        job = getattr(self, "_banner_job", None)
        if job is not None:
            self.after_cancel(job)
            self._banner_job = None
        if self._banner is not None:
            self._banner[0].destroy()
            self._banner = None
        self.banner_holder.configure(height=1)

    def _dismiss_if_current(self, banner):
        if self._banner is not None and self._banner[0] is banner:
            self._dismiss_banner()

    def _on_explain_toggled(self):
        if not self.explain_var.get():
            self._dismiss_banner()

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
        if self._banner is not None:
            self._banner[1].config(wraplength=max(self.winfo_width() - 110, 240))
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

        start = len(self._wrappables)
        head = tk.Frame(body, background=bg)
        head.pack(fill="x")
        size = t.sp(22)
        badge = tk.Canvas(head, width=size, height=size, background=bg, highlightthickness=0)
        badge.create_oval(1, 1, size - 1, size - 1, fill=color, outline="")
        badge.create_text(size / 2, size / 2, text="✕" if bad else "!", fill="#1a0b0b",
                          font=t.font("caption_bold"))
        badge.pack(side="left", padx=(0, t.sp("sm")))
        if item.get("sender"):      # packed before the headline so a long headline never hides it
            tk.Label(head, text=time.strftime("%H:%M", time.localtime(item["ts"])),
                     background=bg, foreground=t.fg_secondary,
                     font=t.font("caption")).pack(side="right", padx=(t.sp("sm"), 0))
        headline = tk.Label(head, text=info["headline"], background=bg, foreground=color,
                            font=t.font("body_bold"), anchor="w", justify="left")
        headline.pack(side="left", fill="x", expand=True)
        self._wrappables.append((headline, 150))

        explain = tk.Label(body, text=info["explain"], background=bg, foreground=t.fg_primary,
                           font=t.font("body"), justify="left", anchor="w")
        explain.pack(fill="x", pady=(t.sp("xs"), t.sp("xs")))
        self._wrappables.append((explain, 90))
        caught = tk.Frame(body, background=bg)
        caught.pack(fill="x")
        tk.Label(caught, text="Caught by", background=bg, foreground=t.fg_secondary,
                 font=t.font("caption")).pack(side="left", padx=(0, t.sp("sm")))
        check_chip = widgets.Chip(caught, t, info["check"], "bad_dark" if bad else "warn_dark")
        check_chip.configure(justify="left", anchor="w")
        check_chip.pack(side="left", fill="x", expand=True)
        self._wrappables.append((check_chip, 230))     # a long check name wraps instead of clipping
        if info.get("detail"):
            detail = tk.Label(body, text=str(info["detail"]), background=bg,
                              foreground=t.fg_hint, font=t.font("mono_small"),
                              justify="left", anchor="w")
            detail.pack(fill="x", pady=(t.sp("xs"), 0))
            self._wrappables.append((detail, 90))
        w = self.bubble_canvas.winfo_width()
        for label, margin in self._wrappables[start:]:
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
            canvas.configure(cursor=hand_cursor())
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
        win.configure(background=t.bg_app)
        win.resizable(False, False)
        win.transient(self)
        win.bind("<Escape>", lambda _e: win.destroy())
        self._receipt_window = win

        body = tk.Frame(win, background=t.bg_app, padx=t.sp("lg"), pady=t.sp("lg"))
        body.pack(fill="both", expand=True)
        sent = receipt.get("direction") == "sent"
        head = tk.Frame(body, background=t.bg_app)
        head.pack(fill="x", pady=(0, t.sp("md")))
        mark = tk.Canvas(head, width=t.sp(36), height=t.sp(40), background=t.bg_app,
                         highlightthickness=0)
        widgets.draw_shield(mark, t.sp(18), t.sp(20), t.sp(36), fill=t.bg_accent, outline=t.accent)
        widgets.draw_check(mark, t.sp(18), t.sp(21), t.sp(28), t.fg_on_accent, width=3)
        mark.pack(side="left", padx=(0, t.sp("md")))
        titles = tk.Frame(head, background=t.bg_app)
        titles.pack(side="left")
        tk.Label(titles, text="Security receipt", background=t.bg_app, foreground=t.fg_primary,
                 font=t.font("title")).pack(anchor="w")
        tk.Label(titles, text="Message you sent" if sent else f"Message you received from "
                 f"{receipt.get('sender')}", background=t.bg_app, foreground=t.fg_secondary,
                 font=t.font("caption")).pack(anchor="w")

        # -- the checks this message passed (green), or was flagged on (amber) --
        checks = widgets.make_card(body, t, padx="md", pady="sm")
        checks.pack(fill="x")
        for kind, title, detail in receipt_rows(receipt):
            color = t.success if kind == "ok" else t.warning
            row = tk.Frame(checks, background=t.bg_panel)
            row.pack(fill="x", pady=t.sp("xs"))
            size = t.sp(22)
            badge = tk.Canvas(row, width=size, height=size, background=t.bg_panel,
                              highlightthickness=0)
            badge.create_oval(1, 1, size - 1, size - 1, fill=color, outline="")
            if kind == "ok":
                widgets.draw_check(badge, size / 2, size / 2 + 1, size * 0.8, "#052e16", width=2)
            else:
                badge.create_text(size / 2, size / 2, text="!", fill="#2b1d00",
                                  font=t.font("caption_bold"))
            badge.pack(side="left", anchor="n", padx=(0, t.sp("md")))
            text = tk.Frame(row, background=t.bg_panel)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=title, background=t.bg_panel, foreground=color,
                     font=t.font("body_bold"), anchor="w").pack(anchor="w")
            tk.Label(text, text=detail, background=t.bg_panel, foreground=t.fg_secondary,
                     font=t.font("caption"), anchor="w", justify="left",
                     wraplength=t.sp(380)).pack(anchor="w")

        # -- technical values: truncated, with a Copy button for the full value --
        details = widgets.make_card(body, t, padx="md", pady="sm")
        details.pack(fill="x", pady=(t.sp("md"), 0))
        details.columnconfigure(1, weight=1)
        for r, (label, value, mono) in enumerate(receipt_details(receipt)):
            tk.Label(details, text=label, background=t.bg_panel, foreground=t.fg_hint,
                     font=t.font("caption"), anchor="w").grid(row=r, column=0, sticky="w",
                                                              padx=(0, t.sp("md")), pady=t.sp("xs"))
            tk.Label(details, text=shorten(value) if mono else value, background=t.bg_panel,
                     foreground=t.fg_primary, font=t.font("mono_small" if mono else "caption"),
                     anchor="w", justify="left", wraplength=t.sp(300)).grid(
                row=r, column=1, sticky="w", pady=t.sp("xs"))
            if mono and value != "-":
                copy = widgets.flat_button(details, t, "Copy", lambda: None,
                                           background=t.bg_panel)
                # re-bind (replaces flat_button's click) so the label itself can show "Copied"
                copy.bind("<Button-1>", lambda _e, v=value, w=copy: self._copy_value(w, v))
                copy.grid(row=r, column=2, sticky="e", padx=(t.sp("sm"), 0))

        # -- the plain-English verdict --
        kind, sentence = receipt_summary(receipt)
        color, bg = (t.success, t.bg_success_soft) if kind == "ok" else (t.warning, t.bg_warning_soft)
        verdict = tk.Frame(body, background=bg, highlightbackground=color, highlightcolor=color,
                           highlightthickness=1, padx=t.sp("md"), pady=t.sp("sm"))
        verdict.pack(fill="x", pady=(t.sp("md"), 0))
        tk.Label(verdict, text=sentence, background=bg, foreground=t.fg_primary,
                 font=t.font("body_bold"), anchor="w", justify="left",
                 wraplength=t.sp(430)).pack(anchor="w")

        win.update_idletasks()
        x = self.winfo_rootx() + max((self.winfo_width() - win.winfo_width()) // 2, 0)
        y = self.winfo_rooty() + 70
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        widgets.focus_when_mapped(win)
        return win

    def _copy_value(self, button, value):
        widgets.copy_to_clipboard(self, value)
        button.config(text="Copied ✓")
        self.after(1200, lambda: button.winfo_exists() and button.config(text="Copy"))

    # --- Attack Lab (Stage C) --------------------------------------------------
    #
    # Opt-in, lab-mode-only, and enforced entirely server-side (see
    # server/server.py's ChatServer._handle_lab_control): this panel only sends a
    # request; the server decides whether to honor it. Detection is never claimed here.
    # It comes from the OTHER window's own, unmodified client-side checks (GCM tag, RSA
    # signature, replay window, hash chain, handshake signature). That client reports
    # what it caught to the server, which logs it; each card below reads that record
    # (read-only, like the dashboard) to show "Caught by ..." -- or says plainly that no
    # report has arrived, so the audience should watch the other window.

    _LAB_ACTIONS = [(a["action"], a["label"], a["desc"]) for a in LAB_ATTACKS]

    def _open_attack_lab(self):
        if self.client is None or not self.client.lab_mode:
            return
        if self._lab_window_alive():
            self._lab_window.deiconify()
            widgets.focus_when_mapped(self._lab_window)
            return
        t = self.theme
        win = tk.Toplevel(self)
        win.title("Attack Lab")
        win.configure(background=t.bg_lab_panel)
        win.resizable(False, False)
        win.transient(self)
        win.bind("<Escape>", lambda _e: win.destroy())
        self._lab_window = win
        self._lab_cards = {}

        banner = tk.Frame(win, background=t.bg_lab, padx=t.sp("lg"), pady=t.sp("sm"))
        banner.pack(fill="x")
        tk.Label(banner, text="LAB MODE: relay is acting maliciously on request",
                 background=t.bg_lab, foreground=t.fg_on_accent,
                 font=t.font("heading")).pack(anchor="w")

        body = tk.Frame(win, background=t.bg_lab_panel, padx=t.sp("lg"), pady=t.sp("md"))
        body.pack(fill="both", expand=True)
        tk.Label(body, text=f"Each action targets YOUR OWN next message or handshake "
                            f"({self.client.username}, relayed to {self.client.peer}) and is "
                            f"one-shot: it fires once, then disarms. Esc closes this panel.",
                 background=t.bg_lab_panel, foreground=t.fg_secondary, font=t.font("caption"),
                 wraplength=t.sp(640), justify="left").pack(anchor="w", pady=(0, t.sp("sm")))

        grid = tk.Frame(body, background=t.bg_lab_panel)
        grid.pack(fill="both", expand=True)
        for column in range(2):
            grid.columnconfigure(column, weight=1, uniform="lab")
        for index, attack in enumerate(LAB_ATTACKS):
            self._build_lab_card(grid, attack, index // 2, index % 2)

        self._lab_result_var = tk.StringVar(value=self._lab_last_message)
        tk.Label(body, textvariable=self._lab_result_var, background=t.bg_lab_panel,
                 foreground=t.warning, font=t.font("mono_small"), wraplength=t.sp(640),
                 justify="left", anchor="w").pack(anchor="w", pady=(t.sp("sm"), 0), fill="x")

        for attack in LAB_ATTACKS:
            self._render_lab_card(attack["action"])
        win.update_idletasks()
        x = self.winfo_rootx() + max((self.winfo_width() - win.winfo_width()) // 2, 0)
        y = self.winfo_rooty() + 60
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        widgets.focus_when_mapped(win)

    def _build_lab_card(self, parent, attack, row, column):
        t = self.theme
        card = tk.Frame(parent, background=t.bg_panel, highlightbackground=t.bg_lab,
                        highlightcolor=t.bg_lab, highlightthickness=1,
                        padx=t.sp("md"), pady=t.sp("sm"))
        card.grid(row=row, column=column, sticky="nsew",
                  padx=(0 if column == 0 else t.sp("sm"), t.sp("sm") if column == 0 else 0),
                  pady=(0 if row == 0 else t.sp("sm"), t.sp("sm") if row == 0 else 0))
        head = tk.Frame(card, background=t.bg_panel)
        head.pack(fill="x")
        size = t.sp(34)
        glyph = tk.Canvas(head, width=size, height=size, background=t.bg_panel,
                          highlightthickness=0)
        glyph.create_oval(1, 1, size - 1, size - 1, fill=t.bg_lab, outline="")
        glyph.create_text(size / 2, size / 2, text=attack["glyph"], fill=t.fg_on_accent,
                          font=t.font("heading"))
        glyph.pack(side="left", padx=(0, t.sp("sm")))
        tk.Label(head, text=attack["title"], background=t.bg_panel, foreground=t.fg_primary,
                 font=t.font("heading")).pack(side="left")
        tk.Label(card, text=attack["desc"], background=t.bg_panel, foreground=t.fg_secondary,
                 font=t.font("caption"), wraplength=t.sp(300), justify="left",
                 anchor="w").pack(fill="x", pady=(t.sp("xs"), t.sp("xs")))
        defence = tk.Frame(card, background=t.bg_panel)
        defence.pack(fill="x")
        tk.Label(defence, text="Expected defence", background=t.bg_panel,
                 foreground=t.fg_hint, font=t.font("caption")).pack(anchor="w")
        tk.Label(defence, text=attack["check"], background=t.bg_panel, foreground=t.accent,
                 font=t.font("caption_bold"), wraplength=t.sp(300), justify="left",
                 anchor="w").pack(anchor="w")
        chip = widgets.Chip(card, t, "Not armed", "off")
        chip.configure(wraplength=t.sp(300), justify="left", anchor="w")
        chip.pack(fill="x", pady=(t.sp("xs"), t.sp("sm")))
        button = ttk.Button(card, text=attack["label"], style="Lab.TButton",
                            command=lambda a=attack["action"]: self._arm_lab_action(a))
        button.pack(fill="x")
        self._lab_cards[attack["action"]] = {"card": card, "chip": chip, "button": button}

    def _set_lab_state(self, action, state, detail=None):
        entry = self._lab_state[action]
        entry["state"], entry["detail"] = state, detail
        if state == "fired":
            entry["fired_at"] = time.time()
        self._render_lab_card(action)

    def _render_lab_card(self, action):
        if not self._lab_window_alive():
            return
        entry = self._lab_state[action]
        kind, text = lab_status(entry["state"], action, self.peer or "your peer", entry.get("detail"))
        self._lab_cards[action]["chip"].set(kind, text)

    def _arm_lab_action(self, action):
        if self.client is None:
            return
        self._set_lab_state(action, "arming")
        self._lab_last_message = f"Arming: {LAB_BY_ACTION[action]['label']}..."
        if self._lab_window_alive():
            self._lab_result_var.set(self._lab_last_message)
        threading.Thread(target=self.client.send_lab_control, args=(action,),
                         daemon=True).start()

    def _lab_window_alive(self):
        win = getattr(self, "_lab_window", None)
        return win is not None and bool(win.winfo_exists())

    def _on_lab_control_result(self, data):
        action = data.get("action")
        if action in self._lab_state:
            self._set_lab_state(action, "armed" if data.get("armed") else "rejected",
                                data.get("detail"))
        self._lab_last_message = f"{'Armed' if data.get('armed') else 'Rejected'}: {data.get('detail')}"
        if self._lab_window_alive():
            self._lab_result_var.set(self._lab_last_message)

    def _on_lab_attack_performed(self, data):
        action = data.get("action")
        self._lab_last_message = (f"Performed by relay: {data.get('detail')}\n"
                                  f"(watch {self.peer}'s window for the result)")
        if self._lab_window_alive():
            self._lab_result_var.set(self._lab_last_message)
        if action in self._lab_state:
            self._set_lab_state(action, "fired")
            self.after(LAB_POLL_MS, self._poll_lab_detection)

    def _poll_lab_detection(self):
        """While an attack is waiting for its result, look in the security log for the
        victim's own report of catching it."""
        pending = [a for a, e in self._lab_state.items() if e["state"] in ("fired", "silent")]
        if not pending:
            return
        events = read_events(self.log_path)
        now = time.time()
        for action in pending:
            entry = self._lab_state[action]
            if find_lab_detection(action, events, self.peer, entry["fired_at"] - 1.0):
                self._set_lab_state(action, "caught")
            elif entry["state"] == "fired" and now - entry["fired_at"] > LAB_SILENT_AFTER_SECONDS:
                self._set_lab_state(action, "silent")
        if any(e["state"] in ("fired", "silent") for e in self._lab_state.values()):
            self.after(LAB_POLL_MS, self._poll_lab_detection)

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
        if rel.startswith(".."):           # outside the project: the full path is the runnable one
            rel = path
        shown = rel if len(rel) <= 60 else "…/" + "/".join(path.split(os.sep)[-2:])
        self._add_system_notice(
            f"Evidence exported: {shown}\nVerify it independently with:\n"
            f"python tools/verify_transcript.py \"{rel}\"")
        self._append_wire(f"signed evidence file written: {shown}", "INFO")
        self._maybe_banner("evidence_exported", {})

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
        self._handle_event_inner(kind, data)
        if self._chat_ready and kind in ("handshake_established", "message_rejected",
                                         "chain_warning", "handshake_aborted",
                                         "lab_attack_performed"):
            self._maybe_banner(kind, data)

    def _handle_event_inner(self, kind, data):
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
            self._on_lab_control_result(data)
            return

        if kind == "lab_attack_performed":
            self._on_lab_attack_performed(data)
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
            info = describe_rejection(kind, data.get("reason"), data.get("detail"), data)
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
    parser.add_argument("--presentation", action="store_true",
                        help="start in Presentation mode (~25% larger text and padding, for a projector)")
    parser.add_argument("--log-path", default=None,
                        help="security event log the Attack Lab reads results from "
                             "(default: the server's logs/security_events.jsonl)")
    args = parser.parse_args()
    set_app_name("Secure Chat")      # macOS menu bar says "Secure Chat", not "python"
    app = ChatGUI(log_path=args.log_path)
    app.port_var.set(str(args.port))
    if args.presentation:
        app.set_presentation(True)
    if args.geometry:
        app.geometry(args.geometry)
    app.mainloop()


if __name__ == "__main__":
    main()
