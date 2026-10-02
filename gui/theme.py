"""Shared dark theme + font-fallback code for every Tkinter window in this
project (gui/chat_gui.py, gui/security_dashboard.py).

Pulled out of chat_gui.py (Stage D) once a second window needed the exact
same look: same dark palette, same font-availability fallback, same ttk
base styling -- duplicating it would have meant two copies to keep in sync
by hand. Nothing here is specific to the chat window; it only needs a Tk
root to exist (for the font-availability check) and a ttk.Style to apply to.
"""

import sys
import tkinter.font as tkfont

# Font fallback: "Poppins" is a nice-looking modern font but is NOT installed
# by default on Windows/macOS/most Linux distros -- hardcoding it would
# silently fall back to Tk's ugly default on any machine that doesn't have it
# installed. _pick_font() checks tkinter.font.families() (only queryable
# *after* a Tk root exists) and walks a priority list, returning the first
# family that's actually present.
UI_FONT_PRIORITY = ["Poppins", "Segoe UI", "Helvetica Neue", "Helvetica", "Arial"]
MONO_FONT_PRIORITY = ["Consolas", "Cascadia Mono", "SF Mono", "Menlo", "Courier New", "Courier"]

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
        self.ui_font = _pick_font(UI_FONT_PRIORITY, families)
        self.mono_font = _pick_font(MONO_FONT_PRIORITY, families)

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

        # Stage C: Attack Lab -- deliberately a different hue (amber/orange,
        # not the app's teal or the warning red) so the panel and its
        # trigger button read as "a deliberate lab control", not an error.
        self.bg_lab = "#b05a00"
        self.bg_lab_active = "#c96600"
        self.bg_lab_panel = "#241a0e"
        self.fg_lab_banner = "#ffb84d"

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

        style.configure("Lab.TButton", background=self.bg_lab, foreground="#ffffff",
                         font=(self.ui_font, s(10), "bold"), padding=(14, 8), borderwidth=0)
        style.map("Lab.TButton",
                  background=[("active", self.bg_lab_active), ("disabled", "#3a3a3a")],
                  foreground=[("disabled", "#8a8a8a")])

        style.configure("TPanedwindow", background=self.bg_app)
        style.configure("TScrollbar", background=self.bg_panel, troughcolor=self.bg_app,
                         bordercolor=self.bg_app, arrowcolor=self.fg_secondary)
