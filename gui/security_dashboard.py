"""Security dashboard (Stage D): a read-only window onto
logs/security_events.jsonl.

Deliberately NOT a client of the chat protocol -- it never opens a socket,
never connects to the relay server, and has no SecureChatClient. It only
tails one local file and renders what's in it: live counters per event
type, a colour-coded scrolling event feed, and the accounts currently
locked out (with their remaining lock time, computed from the
"account_locked" events' own retry_after). This mirrors how a real SOC
dashboard works -- reading a log, not instrumenting the thing being
watched -- and keeps it trivially safe to leave open during a demo: it
cannot affect the server or either chat session no matter what it does.

Run:  python gui/security_dashboard.py [--log-path logs/security_events.jsonl]
"""

import argparse
import os
import sys
import tkinter as tk
from collections import Counter
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.theme import Theme  # noqa: E402
from server.security_log import DEFAULT_LOG_PATH, read_events  # noqa: E402

POLL_INTERVAL_MS = 500
FEED_MAX_LINES = 500

# Colour coding, by event severity -- "warning" tags the kind that are
# always a live defense working (an attack or abuse attempt actually
# caught), vs. plain "info" for routine activity.
_WARNING_EVENTS = {
    "failed_login", "account_locked", "lockout_rejected", "address_rate_limited",
    "non_tls_connection", "malformed_envelope", "lab_control_rejected",
    "lab_attack_performed", "security_alert",
}


class SecurityDashboard(tk.Tk):
    def __init__(self, log_path=DEFAULT_LOG_PATH):
        super().__init__()
        self.log_path = log_path
        self.title("Security Dashboard")
        self.geometry("920x620")
        self.minsize(640, 420)

        self.theme = Theme(self)
        self.configure(background=self.theme.bg_app)
        style = ttk.Style(self)
        self.theme.apply_ttk(style)

        self._seen_count = 0           # how many lines of the log we've already rendered
        self._counts = Counter()       # event type -> running total
        self._counter_labels = {}      # event type -> tk.Label (created lazily, as seen)
        self._locked = {}              # username -> {"locked_until", "remaining", "lock_level"}

        self._build_layout()
        self._poll()

    # --- layout -----------------------------------------------------------

    def _build_layout(self):
        t = self.theme
        top = tk.Frame(self, background=t.bg_lab, padx=16, pady=10)
        top.pack(side="top", fill="x")
        tk.Label(top, text="SECURITY DASHBOARD -- read-only, not connected to the server",
                 background=t.bg_lab, foreground="#ffffff",
                 font=(t.ui_font, t.size(11), "bold")).pack(side="left")
        # Show the log path relative to the project when it lives inside it: the
        # absolute path is long enough to be clipped next to the title.
        shown = os.path.relpath(self.log_path, os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        if shown.startswith(".."):
            shown = self.log_path
        self.path_var = tk.StringVar(value=f"watching: {shown}")
        tk.Label(top, textvariable=self.path_var, background=t.bg_lab, foreground="#ffe8c8",
                 font=(t.mono_font, t.size(8))).pack(side="right")

        body = tk.Frame(self, background=t.bg_app, padx=12, pady=10)
        body.pack(fill="both", expand=True)

        # -- counters row --
        self.counters_frame = tk.Frame(body, background=t.bg_panel, padx=12, pady=10)
        self.counters_frame.pack(side="top", fill="x", pady=(0, 10))
        tk.Label(self.counters_frame, text="Event counts", background=t.bg_panel,
                 foreground=t.fg_secondary, font=(t.ui_font, t.size(9), "bold")).grid(
            row=0, column=0, sticky="w", padx=(0, 16))
        self._counters_row = 0
        self._counters_col = 1

        # -- split pane: locked accounts (left) / live feed (right) --
        paned = ttk.Panedwindow(body, orient="horizontal")
        paned.pack(fill="both", expand=True)

        locked_pane = tk.Frame(paned, background=t.bg_panel)
        ttk.Label(locked_pane, text="Locked accounts", style="SectionTitle.TLabel",
                 background=t.bg_panel, padding=(10, 8, 10, 4)).pack(anchor="w")
        self.locked_list = tk.Frame(locked_pane, background=t.bg_panel)
        self.locked_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.locked_empty_label = tk.Label(self.locked_list, text="No accounts currently locked.",
                                           background=t.bg_panel, foreground=t.fg_secondary,
                                           font=(t.ui_font, t.size(9)))
        self.locked_empty_label.pack(anchor="w")
        paned.add(locked_pane, weight=1)

        feed_pane = tk.Frame(paned, background=t.bg_panel_alt)
        ttk.Label(feed_pane, text="Live event feed", style="SectionTitle.TLabel",
                 background=t.bg_panel_alt, padding=(10, 8, 10, 4)).pack(anchor="w")
        feed_body = tk.Frame(feed_pane, background=t.bg_panel_alt)
        feed_body.pack(fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        self.feed_text = tk.Text(feed_body, wrap="word", state="disabled",
                                  font=(t.mono_font, t.size(9)), background=t.bg_panel_alt,
                                  foreground=t.wire_info, borderwidth=0, highlightthickness=0,
                                  padx=8, pady=6)
        feed_scroll = ttk.Scrollbar(feed_body, orient="vertical", command=self.feed_text.yview)
        self.feed_text.configure(yscrollcommand=feed_scroll.set)
        self.feed_text.pack(side="left", fill="both", expand=True)
        feed_scroll.pack(side="right", fill="y")
        self.feed_text.tag_config("warning", foreground=t.wire_warning,
                                  font=(t.mono_font, t.size(9), "bold"))
        self.feed_text.tag_config("info", foreground=t.wire_info)
        paned.add(feed_pane, weight=2)

    # --- polling: read whatever is new in the log, render it -------------

    def _poll(self):
        events = read_events(self.log_path)
        new = events[self._seen_count:]
        if new:
            self._seen_count = len(events)
            for event in new:
                self._counts[event["event"]] += 1
                self._append_feed(event)
            self._refresh_counters()
        self._recompute_locked(events)
        self.after(POLL_INTERVAL_MS, self._poll)

    def _append_feed(self, event):
        import time as _time
        t = self.theme
        ts = _time.strftime("%H:%M:%S", _time.localtime(event.get("ts", 0)))
        etype = event.get("event", "?")
        detail_parts = [f"{k}={v}" for k, v in event.items() if k not in ("ts", "event")]
        line = f"[{ts}] {etype}: {', '.join(detail_parts)}\n"
        tag = "warning" if etype in _WARNING_EVENTS else "info"

        self.feed_text.config(state="normal")
        self.feed_text.insert("end", line, (tag,))
        # Cap the feed so a long-running demo doesn't grow Tk's Text widget
        # unboundedly -- the full history is still in the log file itself.
        line_count = int(self.feed_text.index("end-1c").split(".")[0])
        if line_count > FEED_MAX_LINES:
            self.feed_text.delete("1.0", f"{line_count - FEED_MAX_LINES}.0")
        self.feed_text.see("end")
        self.feed_text.config(state="disabled")

    def _refresh_counters(self):
        t = self.theme
        for etype, count in sorted(self._counts.items()):
            label = self._counter_labels.get(etype)
            if label is None:
                color = t.fg_warning if etype in _WARNING_EVENTS else t.fg_accent
                cell = tk.Frame(self.counters_frame, background=t.bg_panel)
                cell.grid(row=self._counters_row, column=self._counters_col,
                         sticky="w", padx=(0, 18), pady=2)
                tk.Label(cell, text=f"{etype}:", background=t.bg_panel,
                         foreground=t.fg_secondary, font=(t.mono_font, t.size(9))).pack(
                    side="left")
                label = tk.Label(cell, text="", background=t.bg_panel, foreground=color,
                                 font=(t.mono_font, t.size(9), "bold"))
                label.pack(side="left", padx=(4, 0))
                self._counter_labels[etype] = label
                self._counters_col += 1
                if self._counters_col > 3:
                    self._counters_col = 1
                    self._counters_row += 1
            label.config(text=str(count))

    def _recompute_locked(self, events):
        """Derive the current lock state purely by replaying events (no
        connection to the server's live LockoutGuard -- this window only
        ever reads the log) -- a lock from "account_locked" lasts until its
        recorded retry_after, and a later "user_login" for the same
        username (a successful login, which is the only event server.py
        logs AFTER a real success) clears it early."""
        import time as _time
        locks = {}
        for event in events:
            if event["event"] == "account_locked":
                username = event.get("username")
                locked_until = event.get("ts", 0) + float(event.get("retry_after", 0))
                locks[username] = {"locked_until": locked_until,
                                   "lock_level": event.get("lock_level", 0)}
            elif event["event"] == "user_login":
                locks.pop(event.get("username"), None)

        now = _time.time()
        self._locked = {u: d for u, d in locks.items() if d["locked_until"] > now}
        self._render_locked(now)  # always redraw: remaining-time labels tick every poll

    def _render_locked(self, now):
        t = self.theme
        for child in self.locked_list.winfo_children():
            child.destroy()
        if not self._locked:
            self.locked_empty_label = tk.Label(
                self.locked_list, text="No accounts currently locked.",
                background=t.bg_panel, foreground=t.fg_secondary, font=(t.ui_font, t.size(9)))
            self.locked_empty_label.pack(anchor="w")
            return
        for username, info in sorted(self._locked.items(),
                                     key=lambda kv: -kv[1]["locked_until"]):
            remaining = max(0, int(info["locked_until"] - now))
            row = tk.Frame(self.locked_list, background=t.bg_panel)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=username, background=t.bg_panel, foreground=t.fg_primary,
                     font=(t.ui_font, t.size(10), "bold")).pack(anchor="w")
            # wraplength: this pane is narrow, and an unwrapped line was clipped
            # at its right edge ("retry in 56s (lock...").
            tk.Label(row, text=f"locked -- retry in {remaining}s (lockout #{info['lock_level'] + 1})",
                     background=t.bg_panel, foreground=t.fg_warning,
                     font=(t.mono_font, t.size(9)), wraplength=200, justify="left").pack(anchor="w")


def main():
    parser = argparse.ArgumentParser(description="Security dashboard -- tails "
                                                  "logs/security_events.jsonl")
    parser.add_argument("--log-path", default=DEFAULT_LOG_PATH)
    args = parser.parse_args()
    app = SecurityDashboard(log_path=args.log_path)
    app.mainloop()


if __name__ == "__main__":
    main()
