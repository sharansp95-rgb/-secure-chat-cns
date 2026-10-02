"""Design system shared by every Tkinter window in this project
(gui/chat_gui.py, gui/security_dashboard.py): palette, spacing scale, type scale,
font fallback and the ttk styles.

Presentation only -- nothing here touches the protocol, crypto or any security check.

Palette: one dark neutral family, ONE brand accent (teal), and three signal colours
used with a fixed meaning everywhere:

    teal   brand / secure / primary action
    green  success: a check passed, session established
    red    danger: something was blocked or failed
    amber  warning: Attack Lab ("lab mode") and "waiting"

Every text-on-background pair listed in `Theme.TEXT_PAIRS` is checked to have a WCAG
contrast ratio of at least 4.5:1 (tests/test_theme.py).

Scales: spacing 4/8/12/16/24/32 (`Theme.sp`) and a type scale -- title, heading, body,
caption, mono (`Theme.fonts`) -- used by every window instead of ad-hoc sizes.

Fonts are *named* tkinter Font objects, so "Presentation mode" (`set_presentation`)
can enlarge every label in a window in place, by reconfiguring the fonts.
"""

import sys
import tkinter.font as tkfont

# Font fallback: "Poppins" is nice but NOT installed by default on Windows/macOS/most
# Linux, and hardcoding it would silently fall back to Tk's ugly default. _pick_font()
# walks this list (only queryable once a Tk root exists) and takes the first family
# that is actually present: Poppins -> Segoe UI / SF -> Helvetica.
UI_FONT_PRIORITY = ["Poppins", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"]
MONO_FONT_PRIORITY = ["Consolas", "Cascadia Mono", "SF Mono", "Menlo", "Courier New", "Courier"]

# Tk on macOS renders font points at 72 dpi, so a size that reads fine on Windows
# (96 dpi) comes out roughly 25% smaller there; every size is scaled by this.
_FONT_SCALE = 1.25 if sys.platform == "darwin" else 1.0

PRESENTATION_SCALE = 1.25   # "Presentation mode": fonts and padding ~25% larger

# Spacing scale (pixels at normal size).
SPACING = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24, "xxl": 32}

# Type scale: role -> (points at normal size, weight, mono?)
TYPE_SCALE = {
    "display":      (22, "bold", False),   # big KPI numbers
    "title":        (18, "bold", False),   # window / screen title
    "heading":      (12, "bold", False),   # section / card headings
    "body":         (10, "normal", False),
    "body_bold":    (10, "bold", False),
    "caption":      (9, "normal", False),
    "caption_bold": (9, "bold", False),
    "mono":         (10, "normal", True),  # keys, hashes, ciphertext
    "mono_bold":    (10, "bold", True),
    "mono_small":   (9, "normal", True),
    "mono_small_bold": (9, "bold", True),
}


def _hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def relative_luminance(color):
    def channel(c):
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(c) for c in _hex_to_rgb(color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg, bg):
    """WCAG 2 contrast ratio between two #rrggbb colours (1.0 .. 21.0)."""
    a, b = relative_luminance(fg), relative_luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def _pick_font(priority_list, families):
    for name in priority_list:
        if name in families:
            return name
    return tkfont.nametofont("TkDefaultFont").actual("family")  # Tk's own default, last resort


class Theme:
    """Palette + resolved font families + named fonts + ttk styling.
    Built once a Tk root exists (needed for the font-availability check)."""

    def __init__(self, root):
        self.root = root
        families = set(tkfont.families(root))
        self.ui_font = _pick_font(UI_FONT_PRIORITY, families)
        self.mono_font = _pick_font(MONO_FONT_PRIORITY, families)

        # --- surfaces (dark neutral, slightly blue; not pure black) -----------------
        self.bg_app = "#0d1117"          # window background
        self.bg_panel = "#151b23"        # cards / panels
        self.bg_panel_alt = "#10151c"    # wire log / event feed (a shade darker)
        self.bg_raised = "#1e2733"       # raised elements: chips, secondary buttons
        self.bg_input = "#1e2733"
        self.border = "#2d3748"

        # --- text (all >= 4.5:1 on the surfaces above; see TEXT_PAIRS) --------------
        self.fg_primary = "#e6edf3"
        self.fg_secondary = "#a9b6c6"
        self.fg_hint = "#8e9bad"
        self.fg_disabled = "#6b778a"     # disabled controls only (exempt from 4.5:1)

        # --- brand accent: teal ------------------------------------------------------
        self.accent = "#2dd4bf"          # accent text / icons on dark surfaces
        self.bg_accent = "#0f766e"       # primary button, sent bubble (white text)
        self.bg_accent_hover = "#0b625b"
        self.fg_on_accent = "#ffffff"
        self.bg_accent_soft = "#0d2f2d"  # tinted background behind accent text

        # --- signal colours -----------------------------------------------------------
        self.success = "#4ade80"
        self.bg_success_soft = "#102a1d"
        self.danger = "#ff7b7b"
        self.bg_danger_soft = "#34161a"
        self.bg_danger = "#b42318"       # solid red (white text)
        self.warning = "#fbbf24"         # amber text on dark
        self.bg_warning_soft = "#2b2210"
        self.bg_lab = "#b45309"          # amber solid (white text): Attack Lab
        self.bg_lab_hover = "#9a4607"
        self.bg_lab_panel = "#1f1709"
        self.info = "#7cc4ff"            # TLS / informational blue

        # --- message bubbles ------------------------------------------------------------
        self.bg_bubble_sent = self.bg_accent
        self.bg_bubble_recv = "#222c39"
        self.fg_on_sent = "#f0fdfa"
        self.fg_on_recv = self.fg_primary

        # Avatar fills (white initials on each, all >= 4.5:1).
        self.avatar_colors = ["#0f766e", "#5b5bd6", "#b45309", "#9d3a8d", "#2563a8", "#a1403a"]

        # Wire-log tag colours (per message kind; all legible on bg_panel_alt).
        self.wire_handshake = "#c4b5fd"
        self.wire_chat = "#5eead4"
        self.wire_alert = self.danger
        self.wire_tls = self.info
        self.wire_auth = self.warning
        self.wire_info = "#b4c0cf"

        # --- legacy names (kept so older call sites keep working) ------------------------
        self.fg_accent = self.accent
        self.fg_pending = self.warning
        self.fg_warning = self.danger            # NB: historically the red "warning" text
        self.fg_lab_banner = self.warning
        self.bg_fingerprint = self.bg_accent_soft
        self.bg_pending = self.bg_warning_soft
        self.wire_sent = self.wire_chat
        self.wire_recv = self.wire_handshake
        self.wire_warning = self.danger

        self.presentation = False
        self.factor = 1.0
        self.fonts = {}
        for role in TYPE_SCALE:
            font = tkfont.Font(root=root, name=f"sc_{role}")
            # Don't delete the Tk font from Font.__del__: it may run after the root has
            # been destroyed (window close, tests) and the interpreter is already gone.
            font.delete_font = False
            self.fonts[role] = font
        self._configure_fonts()
        self._style = None

    # -- every (foreground, background) text pair that must be >= 4.5:1 --------------
    @property
    def TEXT_PAIRS(self):
        surfaces = (self.bg_app, self.bg_panel, self.bg_panel_alt, self.bg_raised)
        pairs = [(fg, bg) for fg in (self.fg_primary, self.fg_secondary, self.fg_hint,
                                      self.accent, self.success, self.danger, self.warning,
                                      self.info) for bg in surfaces]
        pairs += [
            (self.fg_on_accent, self.bg_accent), (self.fg_on_accent, self.bg_accent_hover),
            (self.fg_on_sent, self.bg_bubble_sent), (self.fg_on_recv, self.bg_bubble_recv),
            (self.fg_on_accent, self.bg_lab), (self.fg_on_accent, self.bg_lab_hover),
            (self.fg_on_accent, self.bg_danger),
            (self.accent, self.bg_accent_soft), (self.success, self.bg_success_soft),
            (self.danger, self.bg_danger_soft), (self.warning, self.bg_warning_soft),
            (self.fg_primary, self.bg_danger_soft), (self.fg_secondary, self.bg_danger_soft),
            (self.fg_primary, self.bg_lab_panel), (self.fg_secondary, self.bg_lab_panel),
            (self.warning, self.bg_lab_panel),
            (self.fg_secondary, self.bg_bubble_recv), (self.accent, self.bg_bubble_recv),
            (self.wire_handshake, self.bg_panel_alt), (self.wire_chat, self.bg_panel_alt),
            (self.wire_info, self.bg_panel_alt),
        ]
        pairs += [(self.fg_on_accent, c) for c in self.avatar_colors]
        return pairs

    # -- scales -----------------------------------------------------------------------
    def sp(self, step):
        """Spacing in pixels for a scale step ("xs".."xxl" or a raw size), scaled for
        Presentation mode."""
        px = SPACING[step] if isinstance(step, str) else step
        return round(px * self.factor)

    def size(self, points):
        """Font size for `points`, platform- and presentation-scaled (legacy helper;
        prefer the named `fonts`, which also follow Presentation mode live)."""
        return round(points * _FONT_SCALE * self.factor)

    def font(self, role):
        return self.fonts[role]

    def avatar_color(self, name):
        return self.avatar_colors[sum(ord(c) for c in (name or "?")) % len(self.avatar_colors)]

    def _configure_fonts(self):
        for role, (points, weight, mono) in TYPE_SCALE.items():
            self.fonts[role].configure(
                family=self.mono_font if mono else self.ui_font,
                size=round(points * _FONT_SCALE * self.factor), weight=weight)

    def set_presentation(self, on):
        """Switch Presentation mode on/off: every named font and every ttk style grows
        (or shrinks) ~25%. Returns the ratio new/old so a window can also rescale its
        padding and geometry (see gui/widgets.py: rescale_tree)."""
        old = self.factor
        self.presentation = bool(on)
        self.factor = PRESENTATION_SCALE if on else 1.0
        self._configure_fonts()
        if self._style is not None:
            self.apply_ttk(self._style)
        return self.factor / old

    # -- ttk ----------------------------------------------------------------------------
    def apply_ttk(self, style):
        """ttk theming covers Frame/Label/Entry/Button/Panedwindow/Scrollbar. It does NOT
        reach raw Tk widgets (Text, Canvas, tk.Label...) -- those get colours directly
        where they are created."""
        self._style = style
        style.theme_use("clam")  # the ttk base theme that honours custom colours
        f = self.fonts
        pad_x, pad_y = self.sp("lg"), self.sp("sm")

        style.configure(".", background=self.bg_app, foreground=self.fg_primary, font=f["body"])
        style.configure("TFrame", background=self.bg_app)
        style.configure("Panel.TFrame", background=self.bg_panel)
        style.configure("TLabel", background=self.bg_app, foreground=self.fg_primary,
                        font=f["body"])
        style.configure("Panel.TLabel", background=self.bg_panel, foreground=self.fg_primary,
                        font=f["body"])
        style.configure("PanelSecondary.TLabel", background=self.bg_panel,
                        foreground=self.fg_secondary, font=f["body"])
        style.configure("Hint.TLabel", background=self.bg_panel, foreground=self.fg_hint,
                        font=f["caption"])
        style.configure("Secondary.TLabel", background=self.bg_app, foreground=self.fg_secondary,
                        font=f["caption"])
        style.configure("Title.TLabel", background=self.bg_app, foreground=self.fg_primary,
                        font=f["title"])
        style.configure("Header.TLabel", background=self.bg_panel, foreground=self.fg_primary,
                        font=f["heading"])
        style.configure("SectionTitle.TLabel", background=self.bg_panel,
                        foreground=self.fg_secondary, font=f["body_bold"])
        style.configure("Warning.TLabel", background=self.bg_app, foreground=self.danger,
                        font=f["caption_bold"])

        style.configure("TEntry", fieldbackground=self.bg_input, foreground=self.fg_primary,
                        insertcolor=self.fg_primary, bordercolor=self.border,
                        lightcolor=self.bg_input, darkcolor=self.bg_input)
        style.map("TEntry", fieldbackground=[("readonly", self.bg_input)],
                  bordercolor=[("focus", self.accent)])

        def button(name, bg, hover, fg):
            style.configure(name, background=bg, foreground=fg, font=f["body_bold"],
                            padding=(pad_x, pad_y), borderwidth=0, focusthickness=0,
                            focuscolor=bg)
            style.map(name, background=[("disabled", self.bg_raised), ("active", hover)],
                      foreground=[("disabled", self.fg_disabled)])

        button("TButton", self.bg_accent, self.bg_accent_hover, self.fg_on_accent)   # primary
        button("Secondary.TButton", self.bg_raised, "#2a3646", self.fg_primary)
        button("Lab.TButton", self.bg_lab, self.bg_lab_hover, self.fg_on_accent)      # Attack Lab
        button("Danger.TButton", self.bg_danger, "#c9302c", self.fg_on_accent)
        button("Ghost.TButton", self.bg_panel, self.bg_raised, self.fg_secondary)

        style.configure("TPanedwindow", background=self.bg_app)
        style.configure("TScrollbar", background=self.bg_raised, troughcolor=self.bg_app,
                        bordercolor=self.bg_app, arrowcolor=self.fg_secondary)
        style.configure("TMenubutton", background=self.bg_raised, foreground=self.fg_primary,
                        font=f["body_bold"], padding=(pad_x, pad_y), borderwidth=0)
        style.map("TMenubutton", background=[("active", "#2a3646")])
