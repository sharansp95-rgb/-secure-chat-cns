"""Small reusable Tkinter widgets and helpers for the project's windows.

Presentation only: nothing here knows about sockets, keys or the protocol. They are
shared by gui/chat_gui.py and gui/security_dashboard.py so both windows look and behave
the same (see gui/theme.py for the palette, spacing and type scales they use).
"""

import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------------------------
# Presentation-mode helpers
# ---------------------------------------------------------------------------------


def _scale_pad(value, ratio):
    """Scale a Tk padding value (an int, or an (before, after) pair)."""
    if isinstance(value, (tuple, list)):
        return tuple(round(int(v) * ratio) for v in value)
    return round(int(value) * ratio)


def rescale_tree(widget, ratio):
    """Multiply the padding of `widget` and every descendant by `ratio`: pack/grid
    padx/pady/ipadx/ipady plus the internal padx/pady of Frames and Labels.

    Fonts are NOT handled here -- they are named fonts and follow
    Theme.set_presentation() by themselves. Call this after the theme switched, with the
    ratio it returned, so a window grows consistently (text AND breathing room)."""
    for child in widget.winfo_children():
        rescale_tree(child, ratio)
    manager = widget.winfo_manager()
    try:
        if manager == "pack":
            info = widget.pack_info()
            widget.pack_configure(**{k: _scale_pad(info[k], ratio)
                                     for k in ("padx", "pady", "ipadx", "ipady")})
        elif manager == "grid":
            info = widget.grid_info()
            widget.grid_configure(**{k: _scale_pad(info[k], ratio)
                                     for k in ("padx", "pady", "ipadx", "ipady")})
    except (tk.TclError, KeyError):
        pass
    if isinstance(widget, (tk.Frame, tk.Label, tk.Button, tk.Toplevel)):
        for option in ("padx", "pady"):
            try:
                widget.configure(**{option: _scale_pad(widget.cget(option), ratio)})
            except tk.TclError:
                pass


def copy_to_clipboard(widget, text):
    """Put `text` on the system clipboard (via Tk, no extra dependency)."""
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update_idletasks()


# ---------------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------------


def rounded_rect_points(x1, y1, x2, y2, r):
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


def draw_shield(canvas, cx, cy, size, fill, outline="", tags=()):
    """A heraldic shield centred on (cx, cy), `size` px tall."""
    w, h = size * 0.82, size
    x1, y1 = cx - w / 2, cy - h / 2
    pts = [x1, y1 + h * 0.12, cx, y1, x1 + w, y1 + h * 0.12,
           x1 + w, y1 + h * 0.52, cx, y1 + h, x1, y1 + h * 0.52]
    return [canvas.create_polygon(pts, fill=fill, outline=outline, width=1, tags=tags)]


def draw_check(canvas, cx, cy, size, color, width=2, tags=()):
    s = size
    return [canvas.create_line(cx - s * 0.30, cy + s * 0.02, cx - s * 0.08, cy + s * 0.24,
                               cx + s * 0.32, cy - s * 0.22, fill=color, width=width,
                               capstyle="round", joinstyle="round", tags=tags)]


def draw_lock(canvas, cx, cy, size, color, bg, tags=()):
    """A small padlock (body + shackle) centred on (cx, cy)."""
    s = size
    bw, bh = s * 0.56, s * 0.40
    top = cy - s * 0.02
    items = [canvas.create_arc(cx - bw * 0.36, top - s * 0.36, cx + bw * 0.36, top + s * 0.12,
                               start=0, extent=180, style="arc", outline=color,
                               width=max(2, round(s * 0.09)), tags=tags),
             canvas.create_rectangle(cx - bw / 2, top, cx + bw / 2, top + bh, fill=color,
                                     outline=color, tags=tags),
             canvas.create_oval(cx - s * 0.05, top + bh * 0.28, cx + s * 0.05, top + bh * 0.28 + s * 0.10,
                                fill=bg, outline=bg, tags=tags)]
    return items


class Logo(tk.Canvas):
    """The app mark: a teal shield with a padlock, drawn on a Canvas (no image files)."""

    def __init__(self, parent, theme, size=64, background=None):
        bg = background or theme.bg_panel
        super().__init__(parent, width=size, height=size, background=bg,
                         highlightthickness=0, borderwidth=0)
        pad = size * 0.04
        draw_shield(self, size / 2, size / 2, size - 2 * pad, fill=theme.bg_accent,
                    outline=theme.accent)
        draw_lock(self, size / 2, size * 0.50, size * 0.50, theme.fg_on_accent, theme.bg_accent)


class Avatar(tk.Canvas):
    """A filled circle with the person's initial (the colour comes from the name, so a
    given user is always the same colour in every window)."""

    def __init__(self, parent, theme, name, size=36, background=None):
        super().__init__(parent, width=size, height=size, background=background or theme.bg_panel,
                         highlightthickness=0, borderwidth=0)
        self.theme, self.size = theme, size
        self.set_name(name)

    def set_name(self, name):
        self.delete("all")
        s = self.size
        self.create_oval(1, 1, s - 1, s - 1, fill=self.theme.avatar_color(name), outline="")
        self.create_text(s / 2, s / 2, text=(name or "?")[:1].upper(),
                         fill=self.theme.fg_on_accent, font=self.theme.font("heading"))


class Chip(tk.Label):
    """A small rounded-look status pill. kind: "off" (grey), "ok" (green), "info" (teal),
    "warn" (amber), "bad" (red)."""

    KINDS = {
        "off":  ("bg_raised", "fg_secondary"),
        "ok":   ("bg_success_soft", "success"),
        "info": ("bg_accent_soft", "accent"),
        "warn": ("bg_warning_soft", "warning"),
        "bad":  ("bg_danger_soft", "danger"),
    }

    def __init__(self, parent, theme, text, kind="off", mono=False, command=None):
        self.theme = theme
        super().__init__(parent, text=text, font=theme.font("mono_small" if mono else "caption_bold"),
                         padx=theme.sp("sm"), pady=theme.sp("xs") - 1 if theme.sp("xs") > 1 else 1,
                         borderwidth=0)
        self.kind = None
        self.set(kind, text)
        if command:
            self.configure(cursor="pointinghand")
            self.bind("<Button-1>", lambda _e: command())

    def set(self, kind, text=None):
        bg_name, fg_name = self.KINDS[kind]
        self.kind = kind
        self.configure(background=getattr(self.theme, bg_name), foreground=getattr(self.theme, fg_name))
        if text is not None:
            self.configure(text=text)


class PlaceholderText(tk.Text):
    """A multi-line input: Enter sends (<<Send>>), Shift+Enter inserts a newline, grows
    with its content up to `max_lines`, and shows grey placeholder text while empty."""

    def __init__(self, parent, theme, placeholder="", max_lines=4, **kw):
        super().__init__(parent, wrap="word", height=1, borderwidth=0, highlightthickness=1,
                         highlightbackground=theme.border, highlightcolor=theme.accent,
                         background=theme.bg_input, foreground=theme.fg_primary,
                         insertbackground=theme.fg_primary, font=theme.font("body"),
                         padx=theme.sp("md"), pady=theme.sp("sm"), undo=True, **kw)
        self.theme, self.placeholder, self.max_lines = theme, placeholder, max_lines
        self._showing_placeholder = False
        self.tag_configure("placeholder", foreground=theme.fg_hint)
        self.bind("<FocusIn>", lambda _e: self._hide_placeholder())
        self.bind("<FocusOut>", lambda _e: self._show_placeholder())
        self.bind("<KeyRelease>", lambda _e: self._autogrow())
        self.bind("<Return>", self._on_return)
        self.bind("<Shift-Return>", self._on_shift_return)
        self._show_placeholder()

    # --- text access that ignores the placeholder ---
    def get_text(self):
        return "" if self._showing_placeholder else self.get("1.0", "end-1c")

    def set_text(self, text):
        self._hide_placeholder()
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self._autogrow()
        if not text and self.focus_get() is not self:
            self._show_placeholder()

    def _show_placeholder(self):
        if not self._showing_placeholder and not self.get("1.0", "end-1c"):
            self.insert("1.0", self.placeholder, ("placeholder",))
            self._showing_placeholder = True
            self.mark_set("insert", "1.0")

    def _hide_placeholder(self):
        if self._showing_placeholder:
            self.delete("1.0", "end")
            self._showing_placeholder = False

    def _autogrow(self):
        lines = int(self.count("1.0", "end-1c", "displaylines", return_ints=True)[0]) \
            if self.get("1.0", "end-1c") else 1
        self.configure(height=max(1, min(self.max_lines, lines)))

    def _on_return(self, _event):
        self.event_generate("<<Send>>")
        return "break"

    def _on_shift_return(self, _event):
        self._hide_placeholder()
        self.insert("insert", "\n")
        self._autogrow()
        return "break"


class StepList(tk.Frame):
    """A vertical progress list: each step is pending, active, done, error or waiting.
    The login screen ticks these off as the REAL connection steps complete."""

    GLYPH = {"pending": "○", "active": "◔", "done": "✓", "error": "✗", "waiting": "◑"}

    def __init__(self, parent, theme, background=None):
        bg = background or theme.bg_panel
        super().__init__(parent, background=bg)
        self.theme, self.bg = theme, bg
        self._rows = []

    def set_steps(self, texts):
        for row in self._rows:
            row[0].destroy()
        self._rows = []
        t = self.theme
        for text in texts:
            frame = tk.Frame(self, background=self.bg)
            frame.pack(fill="x", pady=(0, t.sp("xs")))
            glyph = tk.Label(frame, text=self.GLYPH["pending"], width=2, background=self.bg,
                             foreground=t.fg_hint, font=t.font("body_bold"))
            glyph.pack(side="left")
            label = tk.Label(frame, text=text, background=self.bg, foreground=t.fg_hint,
                             font=t.font("body"), anchor="w", justify="left", wraplength=360)
            label.pack(side="left", fill="x", expand=True)
            self._rows.append((frame, glyph, label))

    def set(self, index, state, text=None):
        t = self.theme
        _frame, glyph, label = self._rows[index]
        color = {"pending": t.fg_hint, "active": t.accent, "done": t.success,
                 "error": t.danger, "waiting": t.warning}[state]
        glyph.configure(text=self.GLYPH[state], foreground=color)
        label.configure(foreground=t.fg_primary if state in ("done", "active", "waiting")
                        else (t.danger if state == "error" else t.fg_hint),
                        font=t.font("body_bold" if state in ("active", "error") else "body"))
        if text is not None:
            label.configure(text=text)

    def state(self, index):
        glyph = self._rows[index][1].cget("text")
        return next(k for k, v in self.GLYPH.items() if v == glyph)


def make_card(parent, theme, background=None, border=None, padx=None, pady=None):
    """A bordered panel (the one 'card' look used by login, receipt, Attack Lab...)."""
    return tk.Frame(parent, background=background or theme.bg_panel,
                    highlightbackground=border or theme.border, highlightcolor=border or theme.border,
                    highlightthickness=1,
                    padx=theme.sp(padx or "lg"), pady=theme.sp(pady or "lg"))


def flat_button(parent, theme, text, command, kind="secondary", **kw):
    """A small clickable label styled like a button; used where a ttk.Button would
    be too heavy (copy buttons, banner dismiss)."""
    colors = {"secondary": (theme.bg_raised, theme.fg_primary),
              "ghost": (None, theme.fg_secondary)}
    bg, fg = colors[kind]
    parent_bg = kw.pop("background", None) or parent.cget("background")
    label = tk.Label(parent, text=text, background=bg or parent_bg, foreground=fg,
                     font=theme.font("caption_bold"), padx=theme.sp("sm"), pady=2,
                     cursor="pointinghand", **kw)
    label.bind("<Button-1>", lambda _e: command())
    hover = theme.bg_raised if kind == "ghost" else "#2a3646"
    label.bind("<Enter>", lambda _e: label.configure(background=hover))
    label.bind("<Leave>", lambda _e: label.configure(background=bg or parent_bg))
    return label


def scrolled_frame(parent, theme, background=None):
    """A vertically scrolling frame. Returns (outer, inner): pack `outer`, put content in
    `inner`."""
    bg = background or theme.bg_panel
    outer = tk.Frame(parent, background=bg)
    canvas = tk.Canvas(outer, background=bg, borderwidth=0, highlightthickness=0)
    bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, background=bg)
    window = canvas.create_window((0, 0), window=inner, anchor="nw")
    inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
    canvas.configure(yscrollcommand=bar.set)
    canvas.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return outer, inner


class Field(tk.Frame):
    """A single-line input in a bordered box that turns teal on focus and red on error,
    with an optional trailing control (e.g. the show/hide-password toggle)."""

    def __init__(self, parent, theme, textvariable, show="", width=30, trailing=None):
        super().__init__(parent, background=theme.bg_input, highlightthickness=1,
                         highlightbackground=theme.border, highlightcolor=theme.accent)
        self.theme, self.error = theme, False
        self.entry = tk.Entry(self, textvariable=textvariable, show=show, width=width,
                              borderwidth=0, highlightthickness=0, background=theme.bg_input,
                              foreground=theme.fg_primary, insertbackground=theme.fg_primary,
                              disabledbackground=theme.bg_input, font=theme.font("body"),
                              selectbackground=theme.bg_accent, selectforeground="#ffffff")
        self.entry.pack(side="left", fill="x", expand=True, padx=(theme.sp("md"), theme.sp("xs")),
                        pady=theme.sp("sm"))
        if trailing is not None:
            trailing(self).pack(side="right", padx=(0, theme.sp("sm")))
        self.entry.bind("<FocusIn>", lambda _e: self._paint(True))
        self.entry.bind("<FocusOut>", lambda _e: self._paint(False))

    def _paint(self, focused):
        t = self.theme
        self.configure(highlightbackground=t.danger if self.error else (t.accent if focused else t.border),
                       highlightcolor=t.danger if self.error else t.accent)

    def set_error(self, flag):
        self.error = bool(flag)
        self._paint(self.focus_get() is self.entry)
