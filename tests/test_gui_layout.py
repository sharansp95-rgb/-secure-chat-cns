"""The chat window's header, buttons and input row must fit at the smallest window the GUI
allows, and the dashboard/login layouts must not clip.

Regression tests for bugs the Review 2 screenshots exposed (the action buttons squeezed out
of the header, the message box pushed off the bottom, the dashboard path and Locked
accounts pane clipped, the login card too tall). Tk reports each row's REQUIRED width;
if that exceeds the window's width, something is being squeezed out. Skipped
automatically where no display is available.
"""

import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
from gui.theme import is_no_display_error


@pytest.fixture()
def app():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    window.geometry("+10000+10000")  # realize it far off-screen, never flashing
    window.update()
    yield window
    window.update()
    window.destroy()


def _long_header(app):
    app._show_chat_screen()
    app.peer_label.config(text="a_rather_long_username")
    app.me_label.config(text="You: another_long_username")
    app._peer_fingerprint = "57AB D182 C165 53B7"
    app.peer = "a_rather_long_username"
    app._set_session_state("secure", app.peer)
    app.update()


def test_header_rows_fit_the_minimum_window_width(app):
    """The action buttons (and the avatar) always fit, even with very long usernames: they
    are packed first so a long name is clipped instead. The chip row fits as a whole, and
    the long status sentence is dropped on a narrow window."""
    _long_header(app)
    min_width = app.minsize()[0]
    app.geometry(f"{min_width}x600+10000+10000")
    app.update()
    app.update()
    row1 = [w for w in app.header_row1.winfo_children() if w.winfo_manager()
            and w is not app.header_row1.winfo_children()[-1]]
    fixed = sum(w.winfo_reqwidth() for w in (app.avatar, app.lab_button, app.export_button,
                                              app.network_button))
    assert fixed <= app.winfo_width(), f"avatar + action buttons need {fixed}px"
    chips = sum(w.winfo_reqwidth() for w in app.chip_row.winfo_children() if w.winfo_manager())
    assert chips <= app.winfo_width(), f"chip row needs {chips}px but the window is {app.winfo_width()}px"
    assert app._status_hidden, "the long status sentence should be dropped on a narrow window"


@pytest.mark.parametrize("size", ["1040x660", "720x520"])
def test_action_buttons_are_actually_mapped_and_inside_the_window(app, size):
    app.geometry(f"{size}+10000+10000")
    _long_header(app)
    app.update()
    width = app.winfo_width()
    for button in (app.export_button, app.lab_button, app.network_button):
        assert button.winfo_ismapped()
        assert button.winfo_width() > 60, f"{button.cget('text')} squeezed to {button.winfo_width()}px"
        assert button.winfo_rootx() - app.winfo_rootx() + button.winfo_width() <= width


@pytest.mark.parametrize("size", ["1040x660", "680x460"])  # default and minimum
def test_message_box_and_send_button_are_never_clipped(app, size):
    """The input row used to be packed after the expanding split pane, so a taller header
    (or a short window) clipped the message box and Send button."""
    app.geometry(f"{size}+10000+10000")
    app._show_chat_screen()
    app.update()
    bottom = app.winfo_rooty() + app.winfo_height()
    for widget in (app.message_entry, app.send_button):
        assert widget.winfo_ismapped()
        assert widget.winfo_height() > 20, f"{widget} squeezed to {widget.winfo_height()}px"
        assert widget.winfo_rooty() + widget.winfo_height() <= bottom, "runs off the window"


def test_dashboard_shows_a_short_relative_log_path():
    """The dashboard header showed the absolute log path, which was clipped to a fragment
    next to the title; inside the project it must be relative."""
    import gui.security_dashboard as dashboard
    try:
        window = dashboard.SecurityDashboard()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    try:
        window.geometry("+10000+10000")
        window.update()
        assert window.path_var.get() == "watching: logs/security_events.jsonl"
    finally:
        window.update()
        window.destroy()


def test_dashboard_locked_account_text_wraps_instead_of_being_clipped(tmp_path):
    """The 'locked -- retry in Ns (lockout #N)' line is longer than the narrow Locked
    accounts pane and was clipped; it must wrap."""
    import json
    import time as _time
    import gui.security_dashboard as dashboard
    log = tmp_path / "events.jsonl"
    log.write_text(json.dumps({"ts": _time.time(), "event": "account_locked",
                               "username": "carol", "retry_after": 60, "lock_level": 1}) + "\n")
    try:
        window = dashboard.SecurityDashboard(log_path=str(log))
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    try:
        window.geometry("+10000+10000")
        window.update()  # runs the first poll, which renders the locked account
        labels = [w for row in window.locked_list.winfo_children() for w in row.winfo_children()
                  if isinstance(w, tk.Label) and "retry in" in str(w.cget("text"))]
        assert labels, "locked account was not rendered"
        assert all(int(str(l.cget("wraplength"))) > 0 for l in labels)
    finally:
        window.update()
        window.destroy()


def test_dashboard_header_and_locked_pane_fit_at_the_launcher_width():
    """At 700px wide (what demo/start_demo.sh uses) the dashboard header showed
    "/securit" and the Locked accounts pane showed "Locked acco" / "ounts currently":
    both must fit."""
    import gui.security_dashboard as dashboard
    try:
        window = dashboard.SecurityDashboard()  # default log path: shown relative to the project
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    try:
        window.geometry("700x430+10000+10000")
        window.update()
        header = window.path_var and [w for w in window.winfo_children()
                                      if isinstance(w, tk.Frame)][0]
        assert header.winfo_reqwidth() <= 700, "dashboard header is wider than the window"
        assert window.paned.sashpos(0) >= 220, "Locked accounts pane is too narrow"
        assert window.locked_empty_label.winfo_reqwidth() <= window.paned.sashpos(0)
    finally:
        window.update()
        window.destroy()


def test_login_card_fits_in_a_short_window(app):
    """The login card was clipped top and bottom in windows shorter than it is, e.g. when
    several windows share one screen."""
    app.geometry("780x540+10000+10000")
    app.update()
    card = app.login_frame.winfo_children()[0]
    assert card.winfo_reqheight() <= 540, (
        f"login card needs {card.winfo_reqheight()}px but the window is only 540px tall")
