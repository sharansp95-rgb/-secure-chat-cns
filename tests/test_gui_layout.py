"""The chat header must fit at the smallest window the GUI allows.

Regression test for a bug the Review 2 screenshots exposed: the Export
Evidence and Attack Lab buttons shared one row with the long status text and
the big fingerprint banner, so at the default window size they were clipped to
nothing and a user could not see (let alone click) them. Tk reports each
row's REQUIRED width; if that exceeds the window's minimum width, something is
being squeezed out. Skipped automatically where no display is available.
"""

import tkinter as tk

import pytest

import gui.chat_gui as chat_gui


@pytest.fixture()
def app():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    window.geometry("+10000+10000")  # realize it far off-screen, never flashing
    yield window
    window.destroy()


def test_header_rows_fit_the_minimum_window_width(app):
    app._show_chat_screen()
    app.fp_label.config(text="bob's fingerprint: 57AB D182 C165 53B7")
    app._set_session_state("secure", "bob")
    app.update()
    min_width = app.minsize()[0]
    for widget in (app.fp_strip.master, app.export_button.master):
        assert widget.winfo_reqwidth() <= min_width, (
            f"header row needs {widget.winfo_reqwidth()}px but the window may be "
            f"only {min_width}px wide -- widgets would be clipped")


def test_action_buttons_are_actually_mapped_and_inside_the_window(app):
    app.geometry("1040x660+10000+10000")  # the default size
    app._show_chat_screen()
    app.update()
    width = app.winfo_width()
    for button in (app.export_button, app.lab_button):
        assert button.winfo_ismapped()
        assert button.winfo_width() > 40, "button squeezed to (almost) nothing"
        assert button.winfo_rootx() - app.winfo_rootx() + button.winfo_width() <= width


@pytest.mark.parametrize("size", ["1040x660", "780x480"])  # default and minimum
def test_message_box_and_send_button_are_never_clipped(app, size):
    """The input row used to be packed after the expanding split pane, so a
    taller header (or a short window) clipped the message box and Send button."""
    app.geometry(f"{size}+10000+10000")
    app._show_chat_screen()
    app.update()
    bottom = app.winfo_rooty() + app.winfo_height()
    for widget in (app.message_entry, app.send_button):
        assert widget.winfo_ismapped()
        assert widget.winfo_height() > 20, f"{widget} squeezed to {widget.winfo_height()}px"
        assert widget.winfo_rooty() + widget.winfo_height() <= bottom, "runs off the window"


def test_dashboard_shows_a_short_relative_log_path():
    """The dashboard header showed the absolute log path, which was clipped to
    a fragment next to the title; inside the project it must be relative."""
    import gui.security_dashboard as dashboard
    try:
        window = dashboard.SecurityDashboard()
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    try:
        window.geometry("+10000+10000")
        assert window.path_var.get() == "watching: logs/security_events.jsonl"
    finally:
        window.destroy()
