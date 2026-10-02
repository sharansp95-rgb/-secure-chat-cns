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
fallback -- see _pick_font() and the Theme class below. This is presentation
only; nothing in this section touches SecureChatClient or the event shape.

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
import tkinter.font as tkfont
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


# ============================================================================
# Visual theme
# ============================================================================
#
# Font fallback: "Poppins" is a nice-looking modern font but is NOT installed
# by default on Windows/macOS/most Linux distros -- hardcoding it would
# silently fall back to Tk's ugly default on any machine that doesn't have it
# installed. _pick_font() checks tkinter.font.families() (only queryable
# *after* a Tk root exists) and walks a priority list, returning the first
# family that's actually present.
_UI_FONT_PRIORITY = ["Poppins", "Segoe UI", "Helvetica Neue", "Helvetica", "Arial"]
_MONO_FONT_PRIORITY = ["Consolas", "Cascadia Mono", "SF Mono", "Menlo", "Courier New", "Courier"]

# Tk on macOS renders font points at 72 dpi, so a size that reads fine on
# Windows (96 dpi) comes out roughly 25% smaller there. Theme.size() scales
# every font size by this factor so the layout looks the same on both.
_FONT_SCALE = 1.25 if sys.platform == "darwin" else 1.0


def _pick_font(priority_list, families):
    for name in priority_list:
        if name in families:
            return name
    return tkfont.nametofont("TkDefaultFont").actual("family")  # Tk's own default, last resort


class Theme:
    """Dark, high-contrast color palette + the resolved font families.
    Built once a Tk root exists (needed for the font-availability check)."""

    def __init__(self, root):
        families = set(tkfont.families(root))
        self.ui_font = _pick_font(_UI_FONT_PRIORITY, families)
        self.mono_font = _pick_font(_MONO_FONT_PRIORITY, families)

        # Backgrounds -- dark neutral, not pure black (#121212/#1a1a1a read
        # as more deliberate/professional than #000000).
        self.bg_app = "#121212"
        self.bg_panel = "#1a1a1a"       # chat/login panel background
        self.bg_panel_alt = "#17191c"   # wire log: a slightly different dark shade
        self.bg_input = "#242424"
        self.bg_bubble_sent = "#128c7e"      # WhatsApp-teal, sent bubble
        self.bg_bubble_recv = "#2a2a2a"      # dark gray, received bubble
        self.bg_fingerprint = "#0b3d36"      # highlighted strip behind the fingerprint
        self.bg_pending = "#3a2f0b"          # same strip while the handshake is pending
        self.border = "#2a2a2a"

        # Foregrounds -- high contrast against the above.
        self.fg_primary = "#e8e8e8"
        self.fg_secondary = "#999999"
        self.fg_hint = "#7a7a7a"
        self.fg_on_sent = "#eafff9"
        self.fg_on_recv = "#e8e8e8"
        self.fg_accent = "#25d366"          # WhatsApp-green accent (fingerprint, success)
        self.fg_pending = "#f0b429"         # amber: handshake not done yet
        self.fg_warning = "#ff5c5c"

        # Wire log syntax colors (kept from the original design, re-checked
        # for contrast against the new, slightly bluer dark panel shade).
        self.wire_sent = "#7fc7ff"
        self.wire_recv = "#b6f27f"
        self.wire_warning = "#ff5c5c"
        self.wire_info = "#c9c9c9"

    @staticmethod
    def size(points):
        return round(points * _FONT_SCALE)

    def apply_ttk(self, style):
        """ttk theming covers Frame/Label/Entry/Button/Panedwindow/Scrollbar.
        It does NOT reach raw Tk widgets (Text, Canvas) -- those get bg/fg
        set directly wherever they're created below."""
        style.theme_use("clam")  # 'clam' is the ttk base theme that actually
        # honors custom colors well; the default Windows/aqua themes mostly
        # ignore background/foreground options on several widgets.

        s = self.size
        style.configure(".", background=self.bg_app, foreground=self.fg_primary,
                         font=(self.ui_font, s(10)))
        style.configure("TFrame", background=self.bg_app)
        style.configure("Panel.TFrame", background=self.bg_panel)
        style.configure("TLabel", background=self.bg_app, foreground=self.fg_primary,
                         font=(self.ui_font, s(10)))
        style.configure("Panel.TLabel", background=self.bg_panel, foreground=self.fg_primary)
        style.configure("PanelSecondary.TLabel", background=self.bg_panel,
                         foreground=self.fg_secondary)
        style.configure("Hint.TLabel", background=self.bg_panel, foreground=self.fg_hint,
                         font=(self.ui_font, s(9)))
        style.configure("Secondary.TLabel", background=self.bg_app,
                         foreground=self.fg_secondary, font=(self.ui_font, s(9)))
        style.configure("Title.TLabel", background=self.bg_app, foreground=self.fg_primary,
                         font=(self.ui_font, s(15), "bold"))
        style.configure("Header.TLabel", background=self.bg_panel, foreground=self.fg_primary,
                         font=(self.ui_font, s(12), "bold"))
        style.configure("SectionTitle.TLabel", background=self.bg_panel,
                         foreground=self.fg_secondary, font=(self.ui_font, s(10), "bold"))
        style.configure("Warning.TLabel", background=self.bg_app, foreground=self.fg_warning,
                         font=(self.ui_font, s(9), "bold"))

        style.configure("TEntry", fieldbackground=self.bg_input, foreground=self.fg_primary,
                         insertcolor=self.fg_primary, bordercolor=self.bg_input,
                         lightcolor=self.bg_input, darkcolor=self.bg_input)
        style.map("TEntry", fieldbackground=[("readonly", self.bg_input)])

        style.configure("TButton", background=self.bg_bubble_sent, foreground="#ffffff",
                         font=(self.ui_font, s(10), "bold"), padding=(14, 8), borderwidth=0)
        style.map("TButton",
                  background=[("active", "#17a390"), ("disabled", "#3a3a3a")],
                  foreground=[("disabled", "#8a8a8a")])

        style.configure("TPanedwindow", background=self.bg_app)
        style.configure("TScrollbar", background=self.bg_panel, troughcolor=self.bg_app,
                         bordercolor=self.bg_app, arrowcolor=self.fg_secondary)


class ChatGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat (GUI)")
        self.geometry("1040x660")
        self.minsize(780, 480)

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

        card = tk.Frame(outer, background=t.bg_panel, padx=36, pady=32,
                         highlightbackground="#2a2a2a", highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center")

        entry_font = (t.ui_font, t.size(11))
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="Secure Chat", style="Header.TLabel",
                  font=(t.ui_font, t.size(20), "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 4), sticky="w")
        ttk.Label(card, text="Register the first time you use a username, then Login after that.",
                  style="PanelSecondary.TLabel").grid(
            row=1, column=0, columnspan=2, pady=(0, 20), sticky="w")

        # Host and port share one row: they're set once and rarely touched.
        ttk.Label(card, text="Server host", style="Panel.TLabel").grid(
            row=2, column=0, sticky="w", pady=(0, 3))
        ttk.Label(card, text="Server port", style="Panel.TLabel").grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=(0, 3))
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(card, textvariable=self.host_var, width=24, font=entry_font).grid(
            row=3, column=0, sticky="ew", pady=(0, 14), ipady=3)
        ttk.Entry(card, textvariable=self.port_var, width=7, font=entry_font).grid(
            row=3, column=1, sticky="ew", padx=(10, 0), pady=(0, 14), ipady=3)

        fields = [
            # (label, attribute, show-char, hint shown under the field)
            ("Username", "username_var", "", "Your own name in this chat."),
            ("Peer username", "peer_var", "",
             "Who you want to chat with: the other window's username."),
            ("Password", "password_var", "•", None),
        ]
        row = 4
        entries = []
        for label, attr, show, hint in fields:
            ttk.Label(card, text=label, style="Panel.TLabel").grid(
                row=row, column=0, columnspan=2, sticky="w", pady=(0, 3))
            var = tk.StringVar()
            setattr(self, attr, var)
            entry = ttk.Entry(card, textvariable=var, show=show, width=34, font=entry_font)
            entry.grid(row=row + 1, column=0, columnspan=2, sticky="ew",
                       pady=(0, 2 if hint else 18), ipady=3)
            entries.append(entry)
            row += 2
            if hint:
                ttk.Label(card, text=hint, style="Hint.TLabel").grid(
                    row=row, column=0, columnspan=2, sticky="w", pady=(0, 12))
                row += 1

        # Enter moves to the next field; Enter in the password field logs in.
        for current, nxt in zip(entries, entries[1:]):
            current.bind("<Return>", lambda _e, n=nxt: n.focus_set())
        entries[-1].bind("<Return>", lambda _e: self._start_auth("login"))
        self.after(100, entries[0].focus_set)

        button_frame = tk.Frame(card, background=t.bg_panel)
        button_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(4, 4))
        self.register_button = ttk.Button(button_frame, text="Register",
                                           command=lambda: self._start_auth("register"))
        self.register_button.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.login_button = ttk.Button(button_frame, text="Login",
                                        command=lambda: self._start_auth("login"))
        self.login_button.pack(side="left", expand=True, fill="x", padx=(6, 0))
        row += 1

        # A plain tk.Label (not ttk) so its color can switch between neutral
        # progress text and red errors -- see _set_login_status.
        self.login_status = tk.Label(card, text="", background=t.bg_panel,
                                      foreground=t.fg_secondary,
                                      font=(t.ui_font, t.size(9), "bold"),
                                      wraplength=380, justify="left")
        self.login_status.grid(row=row, column=0, columnspan=2, pady=(12, 0), sticky="w")

    def _set_login_status(self, text, error=False):
        self.login_status.config(text=text, foreground=self.theme.fg_warning if error
                                 else self.theme.fg_secondary)

    def _build_chat_screen(self):
        t = self.theme
        frame = tk.Frame(self, background=t.bg_app)
        self.chat_frame = frame

        # -- top bar: identity + session status (left), fingerprint strip (right) --
        top = tk.Frame(frame, background=t.bg_panel, padx=16, pady=10)
        top.pack(side="top", fill="x")
        identity = tk.Frame(top, background=t.bg_panel)
        identity.pack(side="left", anchor="w")
        self.header_var = tk.StringVar(value="")
        ttk.Label(identity, textvariable=self.header_var, style="Header.TLabel").pack(anchor="w")
        self.session_status = tk.Label(identity, text="", background=t.bg_panel,
                                        font=(t.ui_font, t.size(9)))
        self.session_status.pack(anchor="w", pady=(2, 0))

        self.fp_strip = tk.Frame(top, background=t.bg_pending, padx=12, pady=6)
        self.fp_strip.pack(side="right")
        self.fp_label = tk.Label(self.fp_strip, text="", background=t.bg_pending,
                                  font=(t.mono_font, t.size(12), "bold"))
        self.fp_label.pack()

        # -- split pane: bubble conversation (left) / wire log (right) --
        paned = ttk.Panedwindow(frame, orient="horizontal")
        paned.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.paned = paned

        chat_pane = tk.Frame(paned, background=t.bg_panel)
        ttk.Label(chat_pane, text="Conversation", style="SectionTitle.TLabel",
                  padding=(10, 8, 10, 4)).pack(anchor="w")
        self._build_bubble_panel(chat_pane)
        paned.add(chat_pane, weight=3)

        wire_pane = tk.Frame(paned, background=t.bg_panel_alt)
        wire_head = tk.Frame(wire_pane, background=t.bg_panel_alt)
        wire_head.pack(side="top", fill="x")
        ttk.Label(wire_head, text="Wire Log (what actually crosses the network)",
                  style="SectionTitle.TLabel", background=t.bg_panel_alt,
                  padding=(10, 8, 10, 4)).pack(side="left")
        legend = tk.Frame(wire_head, background=t.bg_panel_alt)
        legend.pack(side="right", padx=(0, 10), pady=(8, 4))
        for text, color in (("--> sent", t.wire_sent), ("<-- received", t.wire_recv),
                            ("rejected", t.wire_warning)):
            tk.Label(legend, text=text, background=t.bg_panel_alt, foreground=color,
                     font=(t.mono_font, t.size(8))).pack(side="left", padx=(10, 0))
        # width=40 keeps the Text's *requested* width small, so the
        # Panedwindow's 3:2 weights (not this widget's 80-char default)
        # decide how the window's width is split between the two panes.
        self.wire_text = tk.Text(wire_pane, wrap="word", state="disabled", width=40,
                                  font=(t.mono_font, t.size(9)), background=t.bg_panel_alt,
                                  foreground=t.wire_info, insertbackground=t.fg_primary,
                                  borderwidth=0, highlightthickness=0, padx=10, pady=6)
        wire_scroll = ttk.Scrollbar(wire_pane, orient="vertical", command=self.wire_text.yview)
        self.wire_text.configure(yscrollcommand=wire_scroll.set)
        self.wire_text.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=(0, 6))
        wire_scroll.pack(side="right", fill="y", pady=(0, 6))
        self.wire_text.tag_config("sent", foreground=t.wire_sent)
        self.wire_text.tag_config("recv", foreground=t.wire_recv)
        self.wire_text.tag_config("warning", foreground=t.wire_warning,
                                   font=(t.mono_font, t.size(9), "bold"))
        self.wire_text.tag_config("info", foreground=t.wire_info)
        paned.add(wire_pane, weight=2)

        # -- entry + send --
        entry_frame = tk.Frame(frame, background=t.bg_app, padx=10)
        entry_frame.pack(side="bottom", fill="x", pady=(0, 10))
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(entry_frame, textvariable=self.message_var,
                                        font=(t.ui_font, t.size(11)))
        self.message_entry.pack(side="left", fill="x", expand=True, ipady=5)
        self.message_entry.bind("<Return>", lambda _e: self._on_send())
        self.send_button = ttk.Button(entry_frame, text="Send", command=self._on_send)
        self.send_button.pack(side="left", padx=(8, 0))

    def _set_session_state(self, state, peer, detail=""):
        """Header status line + fingerprint strip colors. `state` is one of
        "pending" (amber), "secure" (green), or "error" (red, shows `detail`)."""
        t = self.theme
        if state == "pending":
            self.session_status.config(
                text=f"●  Waiting for {peer} to come online and complete the handshake...",
                foreground=t.fg_pending)
            self.fp_strip.config(background=t.bg_pending)
            self.fp_label.config(text=f"{peer}'s fingerprint: (handshake not complete yet)",
                                 background=t.bg_pending, foreground=t.fg_pending)
        elif state == "secure":
            self.session_status.config(
                text="●  End-to-end encrypted (ECDH + AES-256-GCM, RSA-signed)",
                foreground=t.fg_accent)
            self.fp_strip.config(background=t.bg_fingerprint)
            self.fp_label.config(background=t.bg_fingerprint, foreground=t.fg_accent)
        else:
            self.session_status.config(text=f"●  {detail}", foreground=t.fg_warning)

    # --- WhatsApp-style bubble conversation panel -----------------------
    #
    # Implementation choice: a Canvas-drawn rounded rectangle behind each
    # message, rather than a plain Frame/Label block. Tkinter's native
    # widgets have no border-radius option at all, but Canvas.create_polygon
    # with smooth=True over a rounded-rectangle point path gives genuinely
    # curved corners for a modest amount of code (see _rounded_rect_points),
    # which reads as a real "bubble" rather than a padded rectangle -- worth
    # the extra complexity here specifically, since this panel is the one
    # most visibly "the chat app" during a demo. Bubbles live inside a
    # standard Tkinter scrollable-frame-on-a-canvas (the idiomatic pattern
    # for scrollable widget lists, since ttk has no native one).

    def _build_bubble_panel(self, parent):
        t = self.theme
        container = tk.Frame(parent, background=t.bg_panel)
        container.pack(side="top", fill="both", expand=True, padx=(6, 0), pady=(0, 6))

        # width=360: a small requested width so the Panedwindow weights decide
        # the split (see the matching note on wire_text).
        self.bubble_canvas = tk.Canvas(container, background=t.bg_panel, width=360,
                                        borderwidth=0, highlightthickness=0)
        self._notice_labels = []
        scrollbar = ttk.Scrollbar(container, orient="vertical",
                                   command=self.bubble_canvas.yview)
        self.bubble_list = tk.Frame(self.bubble_canvas, background=t.bg_panel)

        self.bubble_list.bind(
            "<Configure>",
            lambda _e: self.bubble_canvas.configure(
                scrollregion=self.bubble_canvas.bbox("all")),
        )
        self._bubble_window = self.bubble_canvas.create_window(
            (0, 0), window=self.bubble_list, anchor="nw")
        self.bubble_canvas.bind("<Configure>", self._on_bubble_canvas_resize)
        self.bubble_canvas.configure(yscrollcommand=scrollbar.set)
        self.bubble_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_bubble_canvas_resize(self, event):
        # Keep the inner frame's width matched to the canvas's width so rows
        # (and therefore left/right alignment) resize correctly instead of
        # staying pinned to whatever width they were first drawn at -- and
        # re-wrap system notices to the new width so they never get clipped.
        self.bubble_canvas.itemconfigure(self._bubble_window, width=event.width)
        for label in self._notice_labels:
            label.config(wraplength=max(event.width - 40, 120))

    def _on_mousewheel(self, event):
        """Scroll the conversation only when the pointer is over it (the wire
        log's Text widget scrolls itself). Windows reports deltas in steps of
        120; macOS reports small raw deltas, which the old `delta / 120`
        rounded to 0 -- so take the sign, and the step count when available."""
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None and widget is not self.bubble_canvas:
            widget = widget.master
        if widget is None or event.delta == 0:
            return
        units = max(1, abs(event.delta) // 120)
        self.bubble_canvas.yview_scroll(-units if event.delta > 0 else units, "units")

    @staticmethod
    def _rounded_rect_points(x1, y1, x2, y2, r):
        r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
        return [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]

    def _add_bubble(self, text, align, bg, fg, timestamp_str, sender=None):
        """align: 'e' (right, our own messages) or 'w' (left, peer's).
        `sender`, if given, is drawn as a small accent-colored name line."""
        t = self.theme
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=4, padx=10)

        pad_x, pad_y = 14, 10
        # Cap bubbles at ~70% of the conversation pane so they never run
        # past its edge when the pane is narrow.
        pane_w = self.bubble_canvas.winfo_width()
        max_width = max(160, min(420, int(pane_w * 0.7) - pad_x * 2))
        font = (t.ui_font, t.size(10))
        name_font = (t.ui_font, t.size(9), "bold")
        time_font = (t.ui_font, t.size(8))

        canvas = tk.Canvas(row, background=t.bg_panel, borderwidth=0, highlightthickness=0)

        def measure(**kw):
            item = canvas.create_text(0, 0, anchor="nw", **kw)
            x1, y1, x2, y2 = canvas.bbox(item)
            canvas.delete(item)
            return x2 - x1, y2 - y1

        # Pass 1: measure everything off-window to size the bubble.
        text_w, text_h = measure(text=text, font=font, width=max_width)
        time_w, _ = measure(text=timestamp_str, font=time_font)
        name_w, name_h = measure(text=sender, font=name_font) if sender else (0, 0)
        name_gap = name_h + 2 if sender else 0

        bubble_w = max(text_w, time_w, name_w) + pad_x * 2
        bubble_h = name_gap + text_h + pad_y * 2 + 14  # + room for the timestamp line
        canvas.configure(width=bubble_w, height=bubble_h)

        points = self._rounded_rect_points(1, 1, bubble_w - 1, bubble_h - 1, 14)
        canvas.create_polygon(points, smooth=True, fill=bg, outline=bg)
        if sender:
            canvas.create_text(pad_x, pad_y, text=sender, font=name_font,
                                fill=t.fg_accent, anchor="nw")
        canvas.create_text(pad_x, pad_y + name_gap, text=text, font=font, fill=fg,
                            width=max_width, anchor="nw")
        canvas.create_text(bubble_w - pad_x, bubble_h - pad_y + 2, text=timestamp_str,
                            font=time_font, fill=t.fg_secondary if sender else fg,
                            anchor="se")

        canvas.pack(side="right" if align == "e" else "left")
        self._scroll_bubbles_to_bottom()

    def _add_system_notice(self, text, warning=False):
        """System messages are centered, muted, and deliberately NOT styled
        as a bubble from either side -- they're notices, not chat turns."""
        t = self.theme
        row = tk.Frame(self.bubble_list, background=t.bg_panel)
        row.pack(side="top", fill="x", pady=6, padx=10)
        color = t.fg_warning if warning else t.fg_secondary
        weight = "bold" if warning else "normal"
        wrap = max(self.bubble_canvas.winfo_width() - 40, 120)
        label = tk.Label(row, text=text, background=t.bg_panel, foreground=color,
                          font=(t.ui_font, t.size(9), weight), wraplength=wrap,
                          justify="center")
        label.pack(anchor="center")
        self._notice_labels.append(label)
        self._scroll_bubbles_to_bottom()

    def _scroll_bubbles_to_bottom(self):
        self.bubble_list.update_idletasks()
        self.bubble_canvas.configure(scrollregion=self.bubble_canvas.bbox("all"))
        self.bubble_canvas.yview_moveto(1.0)

    def _show_login_screen(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def _show_chat_screen(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        # Lay the chat screen out now, so the first notices/bubbles are
        # sized against the real pane width rather than an unmapped 1px one.
        # ttk.Panedwindow only applies pane weights on *resize*; the initial
        # split comes from requested widths, so set the divider explicitly.
        self.update_idletasks()
        self.paned.sashpos(0, int(self.paned.winfo_width() * 0.55))
        self.update_idletasks()
        self.message_entry.focus_set()

    # --- login / register (background thread) --------------------------

    def _start_auth(self, mode):
        host = self.host_var.get().strip() or DEFAULT_HOST
        try:
            port = int(self.port_var.get().strip() or DEFAULT_PORT)
        except ValueError:
            self._set_login_status("Port must be a number.", error=True)
            return
        username = self.username_var.get().strip()
        peer = self.peer_var.get().strip()
        password = self.password_var.get()

        if not username or not peer or not password:
            self._set_login_status("Username, peer username, and password are all required.",
                                   error=True)
            return
        if username == peer:
            self._set_login_status("Peer username must be someone else -- the other "
                                   "window's username.", error=True)
            return
        if str(self.register_button.cget("state")) == "disabled":
            return  # an attempt is already in flight (e.g. Enter pressed twice)

        self.register_button.config(state="disabled")
        self.login_button.config(state="disabled")
        verb = "Registering" if mode == "register" else "Logging in"
        self._set_login_status(f"{verb} as {username} via {host}:{port}...")

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
        if kind == "tls_cert_fingerprint":
            self._append_wire(
                f"[tls] trusting server cert fingerprint: {data['fingerprint']}", "info")
            return

        if kind == "auth_error":
            self._set_login_status(f"Failed: {data.get('detail')}", error=True)
            self.register_button.config(state="normal")
            self.login_button.config(state="normal")
            return

        if kind == "auth_success":
            pair = f"{data['username']}  ↔  {data['peer']}"
            self.header_var.set(pair)
            self.title(f"Secure Chat (GUI) — {pair}")
            self._set_session_state("pending", data["peer"])
            self._show_chat_screen()
            if data.get("own_fingerprint"):
                self._add_system_notice(f"Your key fingerprint: {data['own_fingerprint']}")
            if not data.get("peer_key_found"):
                # Normal when this side logs in first: the key is fetched
                # again automatically once the peer joins and starts the
                # handshake (see the "handshake_waiting" event).
                self._add_system_notice(
                    f"{data['peer']} isn't registered or online yet -- the secure "
                    f"session will start automatically when they log in.")
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
            self._add_system_notice(f"Secure session established with {data['peer']}.")
            self._set_session_state("secure", data["peer"])
            return

        if kind == "handshake_aborted":
            msg = f"[handshake] ABORTED with {data['peer']}: {data['reason']}"
            self._append_wire(msg, "warning")
            self._add_system_notice(msg, warning=True)
            self._set_session_state("error", data["peer"], "Handshake aborted -- not secure")
            return

        if kind == "peer_fingerprint":
            fp = data["fingerprint"]
            self.fp_label.config(text=f"{data['peer']}'s fingerprint: {fp}")
            self._append_wire(f"[handshake] {data['peer']}'s RSA key fingerprint: {fp}", "info")
            return

        if kind == "message_sent":
            self._add_bubble(data["message"], "e", self.theme.bg_bubble_sent,
                              self.theme.fg_on_sent, time.strftime("%H:%M"))
            return

        if kind == "message_queued":
            self._add_system_notice(
                f"Message queued until the secure session is ready: {data['message']}")
            return

        if kind == "message_received":
            self._add_bubble(data["message"], "w",
                              self.theme.bg_bubble_recv, self.theme.fg_on_recv,
                              time.strftime("%H:%M"), sender=data["sender"])
            return

        if kind == "message_rejected":
            msg = f"REJECTED message from {data['sender']}: {data['detail']}"
            self._add_system_notice(msg, warning=True)
            self._append_wire(f"[!] {msg}", "warning")
            return

        if kind == "chain_warning":
            # Authentic message(s) are missing before one that DID arrive:
            # the message is still shown, but this is a security event.
            msg = f"CHAIN WARNING from {data['sender']}: {data['detail']}"
            self._add_system_notice(msg, warning=True)
            self._append_wire(f"[!] {msg}", "warning")
            return

        if kind == "system_message":
            self._add_system_notice(data["text"])
            return

        if kind == "disconnected":
            reason = data.get("reason", "")
            self._set_session_state("error", self.peer,
                                    f"Disconnected from server ({reason}) -- restart to reconnect")
            self._add_system_notice("Disconnected from server.", warning=True)
            self.send_button.config(state="disabled")
            self.message_entry.config(state="disabled")
            return

    # --- wire log helper ---------------------------------------------------

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
