"""The chat window: bubbles, date separators, blocked cards, chips, input rules and the
network view. Events a real session produces are fed straight into the window's handler
(no network needed). Presentation only: every "blocked" card is drawn from an event the
client's real checks emitted; nothing here decides what is secure. Skipped where Tk has
no display."""

import tkinter as tk
import time

import pytest

import gui.chat_gui as chat_gui

AUTH = {"username": "alice", "peer": "bob", "lab_mode": True,
        "own_fingerprint": "AAAA BBBB CCCC DDDD", "peer_key_found": True}


@pytest.fixture()
def app():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    window.geometry("1040x660+10000+10000")
    window.update()
    window.username, window.peer = "alice", "bob"
    window._handle_event("auth_success", dict(AUTH))
    window._handoff_to_chat()
    window.update()
    yield window
    window.update()
    window.destroy()


def all_text(app):
    """Every piece of text currently in the conversation (labels and canvas text)."""
    out = []

    def walk(widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                out.append(str(child.cget("text")))
            elif isinstance(child, tk.Canvas):
                out.extend(str(child.itemcget(i, "text")) for i in child.find_all()
                           if child.type(i) == "text")
            walk(child)
    walk(app.bubble_list)
    return "\n".join(out)


def establish(app):
    app._handle_event("peer_fingerprint", {"peer": "bob", "fingerprint": "8860 7244 2628 167C"})
    app._handle_event("handshake_established", {"peer": "bob"})
    app.update()


def test_chips_are_grey_before_the_session_and_green_after(app):
    for chip in (app.chip_tls, app.chip_e2e, app.chip_signed):
        assert chip.kind == "off"
    establish(app)
    for chip in (app.chip_tls, app.chip_e2e, app.chip_signed):
        assert chip.kind == "ok"
    assert app.fp_chip.cget("text").startswith("Key  8860 7244 2628 167C")
    assert app.peer_label.cget("text") == "bob"
    initials = [app.avatar.itemcget(i, "text") for i in app.avatar.find_all()
                if app.avatar.type(i) == "text"]
    assert initials == ["B"]


def test_clicking_the_fingerprint_chip_copies_it(app):
    establish(app)
    app.fp_chip.event_generate("<Button-1>")
    app.update()
    assert app.clipboard_get() == "8860 7244 2628 167C"


def test_send_is_disabled_until_there_is_a_session_and_text(app):
    assert str(app.send_button.cget("state")) == "disabled"
    app.message_entry.set_text("hello")
    app._update_send_state()
    assert str(app.send_button.cget("state")) == "disabled", "no session yet"
    establish(app)
    assert str(app.send_button.cget("state")) == "normal"
    app.message_entry.set_text("   ")
    app._update_send_state()
    assert str(app.send_button.cget("state")) == "disabled", "whitespace only is not a message"


def test_enter_sends_and_shift_enter_inserts_a_newline(app):
    sent = []
    app._on_send = lambda: sent.append(app.message_entry.get_text())
    app.message_entry.bind("<<Send>>", lambda _e: app._on_send())
    app.message_entry.focus_force()
    app.message_entry.set_text("first line")
    app.message_entry.event_generate("<Shift-Return>")
    app.message_entry.insert("end", "second line")
    app.update()
    assert sent == [] and app.message_entry.get_text() == "first line\nsecond line"
    app.message_entry.event_generate("<Return>")
    app.update()
    assert sent == ["first line\nsecond line"]


def test_placeholder_is_shown_when_empty_and_ignored_by_get_text(app):
    assert app.message_entry.get_text() == ""
    assert "Waiting for the secure session" in app.message_entry.get("1.0", "end")
    establish(app)
    app.message_entry.set_text("")
    assert "Enter sends" in app.message_entry.get("1.0", "end")
    app.message_entry.focus_force()
    app.message_entry.event_generate("<KeyPress>", keysym="h")   # the first keystroke clears it
    app.update()
    assert app.message_entry.get_text() == "h"


def test_messages_get_names_times_shield_and_one_date_separator_per_day(app):
    establish(app)
    today = time.time()
    receipt = {"direction": "received", "sender": "bob", "chain_link": "ok"}
    app._handle_event("message_received", {"sender": "bob", "message": "hi alice",
                                           "timestamp": today, "receipt": receipt})
    app._handle_event("message_sent", {"message": "hi bob", "timestamp": today,
                                       "receipt": {"direction": "sent"}})
    app._handle_event("message_received", {"sender": "bob", "message": "old news",
                                           "timestamp": today - 3 * 86400, "receipt": receipt})
    app.update()
    text = all_text(app)
    assert "hi alice" in text and "hi bob" in text
    assert "You" in text and "bob" in text
    assert text.count("Today") == 1, "one separator per day, not per message"
    assert any(i["kind"] == "date" for i in app._items) and len(
        [i for i in app._items if i["kind"] == "date"]) == 2
    assert time.strftime("%H:%M", time.localtime(today)) in text
    # a message with a receipt is clickable and draws a shield
    bubble_canvases = [c for r in app.bubble_list.winfo_children() for c in r.winfo_children()
                       if isinstance(c, tk.Canvas) and c.bind("<Button-1>")]
    assert len(bubble_canvases) == 3


@pytest.mark.parametrize("reason,check", [
    ("decryption_failed", "AES-256-GCM authentication tag"),
    ("replay_duplicate", "Duplicate nonce / timestamp check"),
    ("signature_failed", "RSA signature"),
    ("chain_broken", "Hash chain"),
])
def test_rejected_messages_become_a_blocked_card_naming_the_real_check(app, reason, check):
    establish(app)
    app._handle_event("message_rejected", {"sender": "bob", "reason": reason,
                                           "detail": "the exact detail from the check"})
    app.update()
    text = all_text(app)
    assert "Message blocked:" in text
    assert check in text, "the card must name the check that caught it"
    assert "the exact detail from the check" in text, "the raw detail from the event is kept"
    assert "bob: " not in text  # nothing was displayed as a chat message
    assert [i for i in app._items if i["kind"] == "blocked"][-1]["info"]["severity"] == "bad"


def test_chain_gap_is_an_amber_warning_card_and_flags_the_message(app):
    establish(app)
    app._handle_event("chain_warning", {"sender": "bob", "reason": "chain_gap",
                                        "detail": "1 message(s) missing before #3"})
    app._handle_event("message_received", {
        "sender": "bob", "message": "after the gap", "timestamp": time.time(),
        "receipt": {"direction": "received", "chain_link": "gap"}})
    app.update()
    text = all_text(app)
    assert "Warning: message missing" in text and "Hash-chain sequence number" in text
    assert "after the gap" in text, "an authentic message is still shown (flagged)"
    assert [i for i in app._items if i["kind"] == "blocked"][-1]["info"]["severity"] == "warn"
    assert [i for i in app._items if i["kind"] == "bubble"][-1]["gap"] is True


def test_aborted_handshake_shows_a_card_disables_sending_and_turns_chips_red(app):
    establish(app)
    app._handle_event("handshake_aborted", {
        "peer": "bob", "reason": "the ECDH public key claimed to be from bob did NOT verify "
                                 "against their RSA public key"})
    app.update()
    text = all_text(app)
    assert "Handshake blocked: signature check failed" in text
    assert "RSA signature on the ECDH handshake" in text
    assert str(app.send_button.cget("state")) == "disabled"
    assert app.chip_e2e.kind == "bad" and app.chip_signed.kind == "bad"


def test_network_view_toggle_hides_and_restores_the_wire_pane(app):
    assert app._network_visible and str(app.wire_pane) in [str(p) for p in app.paned.panes()]
    app._toggle_network(False)
    app.update()
    assert str(app.wire_pane) not in [str(p) for p in app.paned.panes()]
    app._toggle_network(True)
    app.update()
    assert str(app.wire_pane) in [str(p) for p in app.paned.panes()]
    # the conversation survives re-rendering
    app._add_system_notice("still here")
    app._toggle_network(False)
    assert "still here" in all_text(app)


def test_narrow_window_starts_with_the_network_view_hidden():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        pytest.skip(f"no display available for Tk: {exc}")
    try:
        window.geometry("720x560+10000+10000")
        window.update()
        window._handle_event("auth_success", dict(AUTH))
        window._handoff_to_chat()
        window.update()
        assert not window._network_visible
    finally:
        window.update()
        window.destroy()


def test_wire_log_lines_are_tagged_by_kind_and_values_are_shortened(app):
    app._handle_event("tls_cert_fingerprint", {"fingerprint": "8D5B 2639 BBAA 8F8C"})
    app._handle_event("envelope_sent", {"envelope": {
        "type": "chat", "from": "alice", "nonce": "N" * 40, "ciphertext": "C" * 60, "tag": "T" * 30}})
    app._handle_event("envelope_received", {"envelope": {
        "type": "handshake_response", "from": "bob", "to": "alice", "pubkey": "P" * 50,
        "handshake_sig": "S" * 80}})
    app._handle_event("message_rejected", {"sender": "bob", "reason": "decryption_failed",
                                           "detail": "tampered"})
    app.update()
    content = app.wire_text.get("1.0", "end")
    for kind in ("TLS", "CHAT", "HANDSHAKE", "ALERT"):
        assert kind in content
    assert "N" * 40 not in content and "C" * 60 not in content, "long values must be truncated"
    assert app.wire_text.tag_ranges("badge_CHAT") and app.wire_text.tag_ranges("badge_ALERT")


def test_a_password_is_never_shown_in_the_network_view(app):
    app._handle_event("envelope_sent", {"envelope": {"type": "login", "username": "alice",
                                                     "password": "hunter2-secret"}})
    assert "hunter2-secret" not in app.wire_text.get("1.0", "end")
