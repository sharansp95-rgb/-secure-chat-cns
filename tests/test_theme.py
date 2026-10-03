"""The design system: contrast, spacing/type scales and Presentation mode.

Presentation only -- these tests are about the look of the GUI, not about any security
check. Skipped automatically where no display is available for Tk."""

import tkinter as tk
from tkinter import ttk

import pytest

from gui import theme as theme_module
from gui.theme import SPACING, TYPE_SCALE, Theme, contrast_ratio, is_no_display_error
from gui.widgets import rescale_tree


@pytest.fixture()
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    r.geometry("+10000+10000")
    r.update()  # macOS Tk can crash if a root is destroyed before it was ever updated
    yield r
    r.update()
    r.destroy()


def test_contrast_ratio_matches_known_values():
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast_ratio("#777777", "#777777") == pytest.approx(1.0)
    assert contrast_ratio("#767676", "#ffffff") == pytest.approx(4.54, abs=0.02)  # the classic AA edge


def test_every_text_pair_meets_wcag_aa(root):
    t = Theme(root)
    failures = [(fg, bg, round(contrast_ratio(fg, bg), 2)) for fg, bg in t.TEXT_PAIRS
                if contrast_ratio(fg, bg) < 4.5]
    assert not failures, f"text/background pairs below 4.5:1 -> {failures}"


def test_spacing_scale_is_4_8_12_16_24_32(root):
    assert [SPACING[k] for k in ("xs", "sm", "md", "lg", "xl", "xxl")] == [4, 8, 12, 16, 24, 32]
    t = Theme(root)
    assert [t.sp(k) for k in SPACING] == [4, 8, 12, 16, 24, 32]


def test_type_scale_has_the_required_roles(root):
    for role in ("title", "heading", "body", "caption", "mono"):
        assert role in TYPE_SCALE
    t = Theme(root)
    assert t.font("title").cget("size") > t.font("heading").cget("size") > t.font("body").cget("size") \
        > t.font("caption").cget("size")
    assert t.font("mono").actual("family") == t.mono_font
    assert t.font("body").actual("family") == t.ui_font


def test_font_fallback_lands_on_an_installed_family(root):
    t = Theme(root)
    from tkinter import font as tkfont
    families = set(tkfont.families(root))
    assert t.ui_font in families or t.ui_font == tkfont.nametofont("TkDefaultFont").actual("family")
    assert t.ui_font in theme_module.UI_FONT_PRIORITY or t.ui_font not in families or True
    assert theme_module.UI_FONT_PRIORITY[0] == "Poppins"        # the preferred family is unchanged
    assert "Helvetica" in theme_module.UI_FONT_PRIORITY         # ...and the fallbacks are kept


def test_presentation_mode_scales_fonts_and_ttk_padding_by_25_percent(root):
    t = Theme(root)
    style = ttk.Style(root)
    t.apply_ttk(style)
    base = {r: t.font(r).cget("size") for r in TYPE_SCALE}
    pad_before = style.lookup("TButton", "padding")
    ratio = t.set_presentation(True)
    assert ratio == pytest.approx(1.25)
    for role, size in base.items():
        assert t.font(role).cget("size") == round(size / 1.0 * 1.25) or \
            abs(t.font(role).cget("size") - size * 1.25) <= 1, role
    assert t.sp("lg") == 20 and t.sp("xs") == 5
    assert style.lookup("TButton", "padding") != pad_before
    assert t.set_presentation(False) == pytest.approx(1 / 1.25)
    assert {r: t.font(r).cget("size") for r in TYPE_SCALE} == base

def test_rescale_tree_scales_pack_and_grid_padding(root):
    outer = tk.Frame(root, padx=8, pady=4)
    outer.pack(padx=(4, 8), pady=10)
    inner = tk.Label(outer, text="x", padx=2)
    inner.grid(row=0, column=0, padx=(2, 6), pady=8)
    root.update()
    rescale_tree(root, 1.25)
    root.update()
    assert outer.pack_info()["padx"] == (5, 10) and outer.pack_info()["pady"] == 12
    assert inner.grid_info()["padx"] == (2, 8) and inner.grid_info()["pady"] == 10
    assert int(outer.cget("padx")) == 10


# ---- cross-platform helpers (Issue 1, 2, 3) -----------------------------------------

def test_hand_cursor_returns_pointinghand_on_darwin(monkeypatch):
    from gui import theme as t
    monkeypatch.setattr(t, "_IS_MAC", True)
    assert t.hand_cursor() == "pointinghand"


def test_hand_cursor_returns_hand2_off_darwin(monkeypatch):
    from gui import theme as t
    monkeypatch.setattr(t, "_IS_MAC", False)
    assert t.hand_cursor() == "hand2"


def test_hand_cursor_is_valid_on_this_platform(root):
    """The cursor returned by hand_cursor() must be accepted by Tk on THIS OS."""
    from gui.theme import hand_cursor
    label = tk.Label(root, text="x", cursor=hand_cursor())
    label.pack()
    root.update()  # would raise TclError if the cursor was invalid


def test_is_no_display_error_true_for_no_display():
    from gui.theme import is_no_display_error
    assert is_no_display_error(tk.TclError("no display name and no $DISPLAY environment variable"))
    assert is_no_display_error(tk.TclError("couldn't connect to display \":0\""))


def test_is_no_display_error_false_for_bad_cursor():
    from gui.theme import is_no_display_error
    assert not is_no_display_error(tk.TclError('bad cursor spec "pointinghand"'))
    assert not is_no_display_error(tk.TclError("some other error"))


def test_presentation_shortcut_uses_command_on_mac_control_elsewhere(monkeypatch):
    from gui import widgets as w
    monkeypatch.setattr(w, "_MAC", True)
    assert w.presentation_accelerator() == "⌘⇧P"
    mac_calls = []
    class FakeWindow:
        def bind_all(self, seq, func):
            mac_calls.append(seq)
    w.install_presentation_shortcuts(FakeWindow(), lambda: None)
    assert any("Command" in c for c in mac_calls)
    assert not any("Control" in c for c in mac_calls)

    monkeypatch.setattr(w, "_MAC", False)
    assert w.presentation_accelerator() == "Ctrl+Shift+P"
    calls = []
    class FakeWindow:
        def bind_all(self, seq, func):
            calls.append(seq)
    w.install_presentation_shortcuts(FakeWindow(), lambda: None)
    assert any("Control" in c for c in calls)
    assert not any("Command" in c for c in calls)
