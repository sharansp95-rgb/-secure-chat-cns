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


# ============================================================================
# Visual theme
from gui.theme import Theme  # noqa: E402



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

        card = tk.Frame(outer, background=t.bg_panel, padx=36, pady=16,
                         highlightbackground="#2a2a2a", highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center")

        entry_font = (t.ui_font, t.size(11))
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="Secure Chat", style="Header.TLabel",
                  font=(t.ui_font, t.size(18), "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 2), sticky="w")
        ttk.Label(card, text="Register the first time you use a username, then Login after that.",
                  style="PanelSecondary.TLabel").grid(
            row=1, column=0, columnspan=2, pady=(0, 10), sticky="w")

        # Host and port share one row: they're set once and rarely touched.
        ttk.Label(card, text="Server host", style="Panel.TLabel").grid(
            row=2, column=0, sticky="w", pady=(0, 3))
        ttk.Label(card, text="Server port", style="Panel.TLabel").grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=(0, 3))
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(card, textvariable=self.host_var, width=24, font=entry_font).grid(
            row=3, column=0, sticky="ew", pady=(0, 8), ipady=2)
        ttk.Entry(card, textvariable=self.port_var, width=7, font=entry_font).grid(
            row=3, column=1, sticky="ew", padx=(10, 0), pady=(0, 8), ipady=2)

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
                       pady=(0, 1 if hint else 12), ipady=2)
            entries.append(entry)
            row += 2
            if hint:
                ttk.Label(card, text=hint, style="Hint.TLabel").grid(
                    row=row, column=0, columnspan=2, sticky="w", pady=(0, 6))
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

        # -- top bar, two rows. Row 1: identity (left) + fingerprint strip
        # (right). Row 2: session status (left) + action buttons (right).
        # They used to share ONE row, where the long status text plus the
        # large fingerprint banner used up the whole width and the right-packed
        # Export Evidence / Attack Lab buttons were clipped to nothing at the
        # default window size.
        top = tk.Frame(frame, background=t.bg_panel, padx=16, pady=10)
        top.pack(side="top", fill="x")
        self.header_var = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.header_var, style="Header.TLabel").pack(
            side="left", anchor="w")

        self.fp_strip = tk.Frame(top, background=t.bg_pending, padx=12, pady=6)
        self.fp_strip.pack(side="right")
        self.fp_label = tk.Label(self.fp_strip, text="", background=t.bg_pending,
                                  font=(t.mono_font, t.size(12), "bold"))
        self.fp_label.pack()

        status_row = tk.Frame(frame, background=t.bg_panel, padx=16)
        status_row.pack(side="top", fill="x")
        self.session_status = tk.Label(status_row, text="", background=t.bg_panel,
                                        font=(t.ui_font, t.size(9)))
        self.session_status.pack(side="left", anchor="w", pady=(0, 10))

        # Stage B: write a signed evidence file for this session.
        self.export_button = ttk.Button(status_row, text="Export Evidence",
                                         command=self._on_export_evidence)
        self.export_button.pack(side="right", pady=(0, 10))

        # Stage C: only enabled once the connected server reports lab_mode
        # (see _handle_event's "auth_success" case) -- a server not started
        # with --lab rejects lab_control anyway, but disabling the button is
        # the honest UI: there is nothing this client could do.
        self.lab_button = ttk.Button(status_row, text="Attack Lab", style="Lab.TButton",
                                     command=self._open_attack_lab, state="disabled")
        self.lab_button.pack(side="right", padx=(0, 8), pady=(0, 10))

        # The input row is packed BEFORE the expanding split pane on purpose:
        # Tk gives space to widgets in packing order, so packing it afterwards
        # let the pane take everything and clipped the message box and Send
        # button whenever the window was short.
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

        # -- split pane: bubble conversation (left) / wire log (right) --
        paned = ttk.Panedwindow(frame, orient="horizontal")
        paned.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.paned = paned

        chat_pane = tk.Frame(paned, background=t.bg_panel)
        chat_head = tk.Frame(chat_pane, background=t.bg_panel)
        chat_head.pack(side="top", fill="x")
        ttk.Label(chat_head, text="Conversation", style="SectionTitle.TLabel",
                  padding=(10, 8, 10, 4)).pack(side="left")
        ttk.Label(chat_head, text="click a message for its security receipt",
                  style="Hint.TLabel").pack(side="right", padx=(0, 10), pady=(8, 4))
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

    def _add_bubble(self, text, align, bg, fg, timestamp_str, sender=None, receipt=None):
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

        if receipt:
            # Stage E: clicking a bubble opens its security receipt.
            canvas.configure(cursor="pointinghand" if sys.platform == "darwin" else "hand2")
            canvas.bind("<Button-1>", lambda _e, r=receipt: self._show_receipt(r))
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
        self._append_wire(f"[evidence] signed evidence file written: {rel}", "info")

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
            if data.get("lab_mode"):
                self.lab_button.config(state="normal")
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
                              self.theme.fg_on_sent, time.strftime("%H:%M"),
                              receipt=data.get("receipt"))
            return

        if kind == "message_queued":
            self._add_system_notice(
                f"Message queued until the secure session is ready: {data['message']}")
            return

        if kind == "message_received":
            self._add_bubble(data["message"], "w",
                              self.theme.bg_bubble_recv, self.theme.fg_on_recv,
                              time.strftime("%H:%M"), sender=data["sender"],
                              receipt=data.get("receipt"))
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
