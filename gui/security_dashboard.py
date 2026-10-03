"""Security dashboard (Stage D): a read-only window onto logs/security_events.jsonl.

Deliberately NOT a client of the chat protocol -- it never opens a socket, never connects
to the relay server, and has no SecureChatClient. It only tails one local file and renders
what is in it: four KPI tiles, a colour-coded live event feed with a readable one-line
description per event (click one for its raw details), and the accounts currently locked
out with a live countdown. This mirrors how a real SOC dashboard works -- reading a log,
not instrumenting the thing being watched -- and keeps it trivially safe to leave open
during a demo: it cannot affect the server or either chat session no matter what it does.

Run:  python gui/security_dashboard.py [--log-path logs/security_events.jsonl]
"""

import argparse
import os
import sys
import time
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui import widgets  # noqa: E402
from gui.macos import set_app_name  # noqa: E402
from gui.explain import compute_kpis, countdown, describe_log_event, locked_accounts  # noqa: E402
from gui.theme import Theme  # noqa: E402
from server.security_log import DEFAULT_LOG_PATH, read_events  # noqa: E402

POLL_INTERVAL_MS = 500       # how often the log is re-read (only when it changed)
TICK_INTERVAL_MS = 1000      # countdown refresh
FLASH_MS = 1400              # how long a KPI tile stays highlighted after it changes
FEED_MAX_LINES = 500
DASH_MIN_HEIGHT = 240
COMPACT_BELOW_HEIGHT = 520   # windows shorter than this drop the subtitle and tile captions

KPI_TILES = [
    # key, label, caption, colour once non-zero
    ("attacks_detected", "Attacks detected", "caught by client checks", "danger"),
    ("failed_logins", "Failed logins", "wrong passwords", "warning"),
    ("locked_accounts", "Locked accounts", "right now", "danger"),
    ("active_users", "Active users", "seen in this log", "success"),
]
COMPACT_LABELS = {"attacks_detected": "Attacks", "failed_logins": "Failed logins",
                  "locked_accounts": "Locked", "active_users": "Active users"}


class SecurityDashboard(tk.Tk):
    def __init__(self, log_path=DEFAULT_LOG_PATH):
        super().__init__()
        self.log_path = log_path
        self.title("Security Dashboard")
        self.geometry("920x620")
        self.minsize(640, DASH_MIN_HEIGHT)

        self.theme = Theme(self)
        self.configure(background=self.theme.bg_app)
        style = ttk.Style(self)
        self.theme.apply_ttk(style)

        self._events = []            # every record read so far
        self._seen_count = 0         # how many of them are already in the feed
        self._signature = None       # (size, mtime) of the log when last read
        self._row_events = {}        # feed row number -> raw record
        self._selected_row = None
        self._kpi_values = {}
        self._captions = []          # (caption label, number label) per KPI tile
        self._tile_parts = {}        # key -> (title label, number label)
        self._compact = False        # short window: one-line header, inline tiles, no captions
        self._density_applied = False
        self._locked = {}            # username -> {"locked_until", "lock_level", "remaining"}

        self.presentation_var = tk.BooleanVar(value=False)
        self._build_layout()
        self._build_menubar()
        widgets.install_presentation_shortcuts(self, self.toggle_presentation)
        # ttk.Panedwindow takes its initial split from requested widths, which left the
        # Locked accounts pane too narrow for its own title and text. (Realize the window
        # first: before it is mapped the pane is ~1px wide and Tk clamps the sash to that.)
        self.update()
        self.paned.sashpos(0, max(240, int(self.paned.winfo_width() * 0.28)))
        self.bind("<Configure>", self._on_configure)
        self._apply_density()
        self._poll()
        self._tick()

    # --- layout -----------------------------------------------------------------------

    def _build_layout(self):
        t = self.theme
        header = tk.Frame(self, background=t.bg_panel, padx=t.sp("lg"), pady=t.sp("md"))
        header.pack(side="top", fill="x")
        self.header_frame = header
        top = tk.Frame(header, background=t.bg_panel)
        top.pack(fill="x")
        self._title_label = tk.Label(top, text="Security Dashboard", background=t.bg_panel,
                                     foreground=t.fg_primary, font=t.font("title"))
        self._title_label.pack(side="left")
        widgets.Chip(top, t, "READ-ONLY", "warn").pack(side="left", padx=(t.sp("md"), 0))
        self._header_top = top
        self._subtitle = tk.Label(header, text="Not connected to the server: it only reads the "
                                               "security log.", background=t.bg_panel,
                                  foreground=t.fg_secondary, font=t.font("caption"))
        self._subtitle.pack(anchor="w")
        # Show the log path relative to the project when it lives inside it: the absolute
        # path is long enough to be clipped.
        shown = os.path.relpath(self.log_path, os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        if shown.startswith(".."):             # outside the project: keep it short, not clipped
            parts = self.log_path.split(os.sep)
            shown = "…/" + "/".join(parts[-2:])
        self.path_var = tk.StringVar(value=f"watching: {shown}")
        self._path_label = tk.Label(header, textvariable=self.path_var, background=t.bg_panel,
                                    foreground=t.fg_hint, font=t.font("mono_small"), anchor="w")
        self._path_label.pack(anchor="w")

        body = tk.Frame(self, background=t.bg_app, padx=t.sp("md"), pady=t.sp("md"))
        body.pack(fill="both", expand=True)
        self._body = body

        # -- KPI tiles --
        self.kpi_row = tk.Frame(body, background=t.bg_app)
        self.kpi_row.pack(side="top", fill="x", pady=(0, t.sp("md")))
        self._tiles = {}
        for column, (key, label, caption, _color) in enumerate(KPI_TILES):
            self.kpi_row.columnconfigure(column, weight=1, uniform="kpi")
            tile = tk.Frame(self.kpi_row, background=t.bg_panel, highlightthickness=2,
                            highlightbackground=t.bg_panel, highlightcolor=t.bg_panel)
            tile.grid(row=0, column=column, sticky="nsew",
                      padx=(0 if column == 0 else t.sp("sm"), 0))
            title_label = tk.Label(tile, text=label, background=t.bg_panel,
                                   foreground=t.fg_secondary, font=t.font("body_bold"), anchor="w")
            title_label.pack(anchor="w", padx=t.sp("md"), pady=(t.sp("sm"), 0))
            number = tk.Label(tile, text="0", background=t.bg_panel, foreground=t.fg_primary,
                              font=t.font("display"), anchor="w")
            number.pack(anchor="w", padx=t.sp("md"))
            caption_label = tk.Label(tile, text=caption, background=t.bg_panel,
                                     foreground=t.fg_hint, font=t.font("caption"), anchor="w",
                                     wraplength=t.sp(130), justify="left")
            caption_label.pack(anchor="w", padx=t.sp("md"), pady=(0, t.sp("sm")))
            self._tiles[key] = (tile, number)
            self._captions.append((caption_label, number))
            self._tile_parts[key] = (title_label, number)

        # -- split pane: locked accounts (left) / live feed (right) --
        paned = ttk.Panedwindow(body, orient="horizontal")
        paned.pack(fill="both", expand=True)

        locked_pane = tk.Frame(paned, background=t.bg_panel)
        tk.Label(locked_pane, text="Locked accounts", background=t.bg_panel,
                 foreground=t.fg_secondary, font=t.font("body_bold")).pack(
            anchor="w", padx=t.sp("md"), pady=(t.sp("sm"), t.sp("xs")))
        self.locked_list = tk.Frame(locked_pane, background=t.bg_panel)
        self.locked_list.pack(fill="both", expand=True, padx=t.sp("md"), pady=(0, t.sp("md")))
        self.locked_empty_label = tk.Label(
            self.locked_list, text="No accounts currently locked.", background=t.bg_panel,
            foreground=t.fg_secondary, font=t.font("body"), wraplength=t.sp(200), justify="left")
        self.locked_empty_label.pack(anchor="w")
        paned.add(locked_pane, weight=0)  # fixed width; only the feed stretches
        self.paned = paned

        feed_pane = tk.Frame(paned, background=t.bg_panel_alt)
        self._feed_title = tk.Label(feed_pane, text="Live event feed", background=t.bg_panel_alt,
                                    foreground=t.fg_secondary, font=t.font("body_bold"))
        self._feed_title.pack(anchor="w", padx=t.sp("md"), pady=(t.sp("sm"), 0))
        self._feed_hint = tk.Label(feed_pane, text="click an event for its raw details",
                                   background=t.bg_panel_alt, foreground=t.fg_hint,
                                   font=t.font("caption"))
        self._feed_hint.pack(anchor="w", padx=t.sp("md"), pady=(0, t.sp("xs")))
        self.detail_var = tk.StringVar(value="")
        self.detail_label = tk.Label(feed_pane, textvariable=self.detail_var,
                                     background=t.bg_raised, foreground=t.fg_primary,
                                     font=t.font("mono_small"), anchor="w", justify="left",
                                     wraplength=t.sp(480), padx=t.sp("md"), pady=t.sp("sm"))
        self.detail_label.bind("<Configure>", lambda e: self.detail_label.config(
            wraplength=max(e.width - 2 * t.sp("md"), 120)))
        feed_body = tk.Frame(feed_pane, background=t.bg_panel_alt)
        self._feed_body = feed_body
        # the details bar appears (packed below the feed) the first time an event is clicked
        feed_body.pack(fill="both", expand=True, padx=(t.sp("md"), 0), pady=(0, t.sp("xs")))
        self.feed_text = tk.Text(feed_body, wrap="word", state="disabled", cursor="arrow",
                                 font=t.font("body"), background=t.bg_panel_alt,
                                 foreground=t.fg_primary, borderwidth=0, highlightthickness=0,
                                 padx=t.sp("sm"), pady=t.sp("sm"), spacing1=3, spacing3=3)
        feed_scroll = ttk.Scrollbar(feed_body, orient="vertical", command=self.feed_text.yview)
        self.feed_text.configure(yscrollcommand=feed_scroll.set)
        self.feed_text.pack(side="left", fill="both", expand=True)
        feed_scroll.pack(side="right", fill="y")
        self.feed_text.tag_config("ts", foreground=t.fg_hint, font=t.font("mono_small"))
        for sev, color in (("info", t.fg_secondary), ("ok", t.success), ("warn", t.warning),
                           ("bad", t.danger)):
            self.feed_text.tag_config(f"icon_{sev}", foreground=color, font=t.font("body_bold"))
            self.feed_text.tag_config(f"text_{sev}", foreground=t.fg_primary if sev == "info"
                                      else color)
        self.feed_text.tag_config("selected", background=t.bg_raised)
        self.feed_text.tag_raise("selected")
        paned.add(feed_pane, weight=1)

    # --- Presentation mode (bigger fonts and padding for a projector) ------------------------

    def _build_menubar(self):
        menubar = tk.Menu(self)
        view = tk.Menu(menubar, tearoff=0)
        view.add_checkbutton(label="Presentation mode", accelerator=widgets.presentation_accelerator(),
                             variable=self.presentation_var, command=self._on_presentation_menu)
        menubar.add_cascade(label="View", menu=view)
        self.config(menu=menubar)
        self.view_menu = view

    def toggle_presentation(self):
        self.set_presentation(not self.theme.presentation)

    def _on_presentation_menu(self):
        self.set_presentation(self.presentation_var.get())

    def set_presentation(self, on):
        """~25% larger fonts and padding (or back); the window grows with it, never past the
        screen. Compact mode's height threshold scales with it."""
        on = bool(on)
        self.presentation_var.set(on)
        if on == self.theme.presentation:
            return
        ratio = self.theme.set_presentation(on)
        widgets.rescale_tree(self, ratio)
        t = self.theme
        for caption, _number in self._captions:
            caption.config(wraplength=t.sp(130))
        self.locked_empty_label.config(wraplength=t.sp(200))
        widgets.scale_window(self, ratio)
        self.minsize(self.minsize()[0], DASH_MIN_HEIGHT)    # height min does not scale: compact mode
        self.update_idletasks()
        self.paned.sashpos(0, max(t.sp(240), int(self.paned.winfo_width() * 0.28)))
        self._apply_density()
        self._render_locked()

    # --- density: a short window (e.g. the launcher's bottom strip) gives the feed the room ---

    def _on_configure(self, event):
        if event.widget is self:
            self._apply_density()

    def _apply_density(self):
        """Short window (the launcher's bottom strip): one-line header, tiles shown as
        "label ........ number" rows, no captions or hints -- the feed gets the room."""
        compact = self.winfo_height() < COMPACT_BELOW_HEIGHT * self.theme.factor
        if compact == self._compact and self._density_applied:
            return
        self._compact, self._density_applied = compact, True
        t = self.theme
        self.header_frame.configure(pady=t.sp("xs") if compact else t.sp("md"))
        self._body.configure(pady=t.sp("xs") if compact else t.sp("md"))
        self.kpi_row.pack_configure(pady=(0, t.sp("xs") if compact else t.sp("md")))
        self._title_label.configure(font=t.font("heading" if compact else "title"))
        self._path_label.pack_forget()
        if compact:                                    # path moves up beside the title: one-line header
            self._path_label.pack(in_=self._header_top, side="left", padx=(t.sp("md"), 0))
        else:
            self._path_label.pack(anchor="w", in_=self.header_frame)
        for key, (title_label, number) in self._tile_parts.items():
            title_label.pack_forget()
            number.pack_forget()
            label_text = next(l for k, l, _c, _col in KPI_TILES if k == key)
            if compact:
                title_label.configure(text=COMPACT_LABELS[key])
                title_label.pack(side="left", padx=(t.sp("md"), t.sp("sm")), pady=t.sp("xs"))
                number.pack(side="right", padx=(0, t.sp("md")))
            else:
                title_label.configure(text=label_text)
                title_label.pack(anchor="w", padx=t.sp("md"), pady=(t.sp("sm"), 0))
                number.pack(anchor="w", padx=t.sp("md"))
        if compact:
            self._subtitle.pack_forget()
            self._feed_hint.pack_forget()
            for caption, _number in self._captions:
                caption.pack_forget()
        else:
            self._subtitle.pack(anchor="w", after=self._header_top)
            self._feed_hint.pack(anchor="w", padx=t.sp("md"), pady=(0, t.sp("xs")),
                                 after=self._feed_title)
            for caption, number in self._captions:
                caption.pack(anchor="w", padx=t.sp("md"), pady=(0, t.sp("sm")), after=number)

    # --- polling: read whatever is new in the log, render it ----------------------------

    def _poll(self):
        try:
            stat = os.stat(self.log_path)
            signature = (stat.st_size, stat.st_mtime_ns)
        except OSError:
            signature = None
        if signature != self._signature:        # only re-read when the file changed
            self._signature = signature
            self._events = read_events(self.log_path)
            for event in self._events[self._seen_count:]:
                self._append_feed(event)
            self._seen_count = len(self._events)
            self._refresh_kpis()
        self.after(POLL_INTERVAL_MS, self._poll)

    def _tick(self):
        """Once a second: recompute who is still locked and redraw the countdowns."""
        self._locked = locked_accounts(self._events, time.time())
        self._render_locked()
        self._set_kpi("locked_accounts", len(self._locked))
        self.after(TICK_INTERVAL_MS, self._tick)

    # --- feed ---------------------------------------------------------------------------

    def _append_feed(self, event):
        glyph, severity, text = describe_log_event(event)
        stamp = time.strftime("%H:%M:%S", time.localtime(event.get("ts", 0)))
        row = len(self._row_events) + 1
        self._row_events[row] = event
        tag = f"row{row}"
        w = self.feed_text
        w.config(state="normal")
        w.insert("end", f"{stamp}  ", ("ts", tag))
        w.insert("end", f"{glyph}  ", (f"icon_{severity}", tag))
        w.insert("end", f"{text}\n", (f"text_{severity}", tag))
        w.tag_bind(tag, "<Button-1>", lambda _e, r=row: self._show_details(r))
        # Cap the feed so a long-running demo doesn't grow the Text widget unboundedly --
        # the full history is still in the log file itself.
        line_count = int(w.index("end-1c").split(".")[0])
        if line_count > FEED_MAX_LINES:
            w.delete("1.0", f"{line_count - FEED_MAX_LINES}.0")
        w.see("end")
        w.config(state="disabled")

    def _show_details(self, row):
        event = self._row_events.get(row)
        if event is None:
            return
        if not self.detail_label.winfo_manager():
            self.detail_label.pack(side="bottom", fill="x", before=self._feed_body)
        w = self.feed_text
        if self._selected_row is not None:
            w.tag_remove("selected", "1.0", "end")
        self._selected_row = row
        start = w.tag_ranges(f"row{row}")
        if start:
            w.tag_add("selected", start[0], start[-1])
        details = "   ".join(f"{k}={v}" for k, v in event.items() if k != "ts")
        self.detail_var.set(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.get('ts', 0)))}"
                            f"   {details}")

    # --- KPI tiles ---------------------------------------------------------------------

    def _refresh_kpis(self):
        for key, value in compute_kpis(self._events).items():
            self._set_kpi(key, value)

    def _set_kpi(self, key, value):
        t = self.theme
        tile, number = self._tiles[key]
        color_name = next(c for k, _l, _c, c in KPI_TILES if k == key)
        number.config(text=str(value),
                      foreground=getattr(t, color_name) if value else t.fg_primary)
        previous = self._kpi_values.get(key)
        self._kpi_values[key] = value
        if previous is not None and previous != value:       # flash so the change is noticed
            tile.config(highlightbackground=getattr(t, color_name))
            self.after(FLASH_MS, lambda: tile.winfo_exists() and tile.config(
                highlightbackground=t.bg_panel))

    # --- locked accounts ---------------------------------------------------------------

    def _render_locked(self):
        t = self.theme
        for child in self.locked_list.winfo_children():
            child.destroy()
        if not self._locked:
            self.locked_empty_label = tk.Label(
                self.locked_list, text="No accounts currently locked.", background=t.bg_panel,
                foreground=t.fg_secondary, font=t.font("body"), wraplength=t.sp(200),
                justify="left")
            self.locked_empty_label.pack(anchor="w")
            return
        for username, info in sorted(self._locked.items(), key=lambda kv: -kv[1]["locked_until"]):
            row = tk.Frame(self.locked_list, background=t.bg_danger_soft, padx=t.sp("md"),
                           pady=t.sp("xs") if self._compact else t.sp("sm"))
            row.pack(fill="x", pady=t.sp("xs"))
            if self._compact:                  # one line: name .... countdown
                tk.Label(row, text=username, background=t.bg_danger_soft, foreground=t.fg_primary,
                         font=t.font("body_bold")).pack(side="left")
                tk.Label(row, text=countdown(info["remaining"]), background=t.bg_danger_soft,
                         foreground=t.danger, font=t.font("heading")).pack(side="right")
                continue
            tk.Label(row, text=username, background=t.bg_danger_soft, foreground=t.fg_primary,
                     font=t.font("body_bold")).pack(anchor="w")
            tk.Label(row, text=countdown(info["remaining"]), background=t.bg_danger_soft,
                     foreground=t.danger, font=t.font("display")).pack(anchor="w")
            # wraplength: this pane is narrow, and an unwrapped line was clipped at its
            # right edge ("retry in 56s (lock...").
            tk.Label(row, text=f"locked, retry in {int(info['remaining'])}s "
                               f"(lockout #{int(info['lock_level']) + 1})",
                     background=t.bg_danger_soft, foreground=t.fg_secondary,
                     font=t.font("caption"), wraplength=t.sp(200), justify="left").pack(anchor="w")


def main():
    parser = argparse.ArgumentParser(description="Security dashboard -- tails "
                                                  "logs/security_events.jsonl")
    parser.add_argument("--log-path", default=DEFAULT_LOG_PATH)
    parser.add_argument("--geometry", help="initial window size/position, e.g. 700x480+560+40")
    parser.add_argument("--presentation", action="store_true",
                        help="start in Presentation mode (~25% larger text and padding, for a projector)")
    args = parser.parse_args()
    set_app_name("Secure Chat")      # macOS menu bar says "Secure Chat", not "python"
    app = SecurityDashboard(log_path=args.log_path)
    if args.presentation:
        app.set_presentation(True)
    if args.geometry:
        app.geometry(args.geometry)
    app.mainloop()


if __name__ == "__main__":
    main()
