"""Presentation mode: ~25% larger fonts and padding in EVERY window (Cmd+Shift+P or the View
menu, or --presentation), and back again. Presentation only; it never touches the protocol.
Skipped where Tk has no display."""

import os
import subprocess
import sys
import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
import gui.security_dashboard as dashboard
from gui import widgets
from gui.theme import TYPE_SCALE

AUTH = {"username": "alice", "peer": "bob", "lab_mode": True,
        "own_fingerprint": "AAAA BBBB CCCC DDDD", "peer_key_found": True}


class FakeClient:
    lab_mode = True
    username, peer = "alice", "bob"

    def send_lab_control(self, action, target=None):
        pass


@pytest.fixture()
def chat(tmp_path):
    try:
        window = chat_gui.ChatGUI(log_path=str(tmp_path / "e.jsonl"))
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    window.geometry("1040x660+10000+10000")
    window.update()
    window.client, window.username, window.peer = FakeClient(), "alice", "bob"
    window._handle_event("auth_success", dict(AUTH))
    window._handoff_to_chat()
    window._handle_event("handshake_established", {"peer": "bob"})
    window.update()
    yield window
    window.update()
    for child in window.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()
    window.update()
    window.destroy()


@pytest.fixture()
def dash(tmp_path):
    try:
        window = dashboard.SecurityDashboard(log_path=str(tmp_path / "e.jsonl"))
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    window.geometry("920x620+10000+10000")
    window.update()
    yield window
    window.update()
    window.destroy()


def sizes(window):
    return {role: window.theme.font(role).cget("size") for role in TYPE_SCALE}


@pytest.mark.parametrize("fixture", ["chat", "dash"])
def test_fonts_and_padding_grow_by_a_quarter_and_come_back(request, fixture):
    window = request.getfixturevalue(fixture)
    base_sizes = sizes(window)
    base_pad = window.theme.sp("lg")
    window.set_presentation(True)
    window.update()
    for role, size in base_sizes.items():
        assert abs(window.theme.font(role).cget("size") - size * 1.25) <= 1, role
    assert window.theme.sp("lg") == round(base_pad * 1.25)
    window.set_presentation(False)
    window.update()
    assert sizes(window) == base_sizes and window.theme.sp("lg") == base_pad


@pytest.mark.parametrize("fixture", ["chat", "dash"])
def test_window_grows_but_never_past_the_screen(request, fixture):
    window = request.getfixturevalue(fixture)
    before = (window.winfo_width(), window.winfo_height())
    window.set_presentation(True)
    window.update()
    assert window.winfo_width() > before[0] and window.winfo_height() > before[1]
    assert window.winfo_width() <= window.winfo_screenwidth()
    assert window.winfo_height() <= window.winfo_screenheight()
    window.set_presentation(False)
    window.update()
    assert abs(window.winfo_width() - before[0]) <= 2 and abs(window.winfo_height() - before[1]) <= 2


def test_chat_padding_of_real_widgets_scales(chat):
    pad_before = int(str(chat.header_frame.cget("padx")))
    row_pad = chat.header_row1.pack_info()["pady"]
    chat.set_presentation(True)
    chat.update()
    assert int(str(chat.header_frame.cget("padx"))) == round(pad_before * 1.25)
    assert chat.header_row1.pack_info()["pady"] == round(int(row_pad) * 1.25) or row_pad == 0


def test_conversation_is_redrawn_at_the_new_size(chat):
    chat._handle_event("message_received", {"sender": "bob", "message": "hello there",
                                           "timestamp": 1_800_000_000, "receipt": {}})
    chat.update()
    bubbles = lambda: [c for r in chat.bubble_list.winfo_children() for c in r.winfo_children()
                       if isinstance(c, tk.Canvas) and int(c.cget("height")) > 40]
    before = max(int(c.cget("height")) for c in bubbles())
    chat.set_presentation(True)
    chat.update()
    assert max(int(c.cget("height")) for c in bubbles()) > before
    assert len([i for i in chat._items if i["kind"] == "bubble"]) == 1, "nothing lost"


def test_avatar_and_logo_are_resized_with_the_text(chat):
    avatar, logo = int(chat.avatar.cget("width")), int(chat.login_logo.cget("width"))
    chat.set_presentation(True)
    assert int(chat.avatar.cget("width")) > avatar and int(chat.login_logo.cget("width")) > logo


def test_open_attack_lab_is_rebuilt_larger(chat):
    chat._open_attack_lab()
    chat.update()
    before = chat._lab_window.winfo_reqwidth()
    chat.set_presentation(True)
    chat.update()
    assert chat._lab_window_alive() and chat._lab_window.winfo_reqwidth() > before


@pytest.mark.parametrize("fixture", ["chat", "dash"])
def test_keyboard_shortcut_and_view_menu_are_wired(request, fixture):
    window = request.getfixturevalue(fixture)
    prefix = "Command" if sys.platform == "darwin" else "Control"
    assert window.bind_all(f"<{prefix}-Shift-P>"), "Cmd+Shift+P (Ctrl+Shift+P) must be bound"
    labels = [window.view_menu.entrycget(i, "label")
              for i in range(window.view_menu.index("end") + 1)]
    assert "Presentation mode" in labels
    window.view_menu.invoke(labels.index("Presentation mode"))
    assert window.theme.presentation, "the menu item toggles it"
    window.toggle_presentation()
    assert not window.theme.presentation


@pytest.mark.parametrize("script", ["gui/chat_gui.py", "gui/security_dashboard.py"])
def test_presentation_flag_exists_on_the_command_line(script):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, script, "--help"], capture_output=True, text=True,
                         cwd=root, timeout=30)
    assert out.returncode == 0 and "--presentation" in out.stdout


def test_dashboard_compact_threshold_scales_with_the_mode(dash):
    dash.geometry("1000x600+10000+10000")
    dash.update()
    assert not dash._compact, "600px tall is roomy at normal size"
    dash.theme.set_presentation(True)       # same window, bigger text: now it IS cramped
    dash._apply_density()
    assert dash._compact
    dash.theme.set_presentation(False)
