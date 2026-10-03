"""The login screen: inline validation, Enter/show-hide behaviour and the step-by-step
progress list that is ticked off by REAL events (no network needed: the events a real
connection produces are fed straight into the window's event handler).

Presentation only. Skipped automatically where no display is available."""

import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
from gui.chat_gui import validate_login_form
from gui.theme import is_no_display_error


@pytest.fixture()
def app():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    window.geometry("780x540+10000+10000")
    window.update()
    yield window
    window.update()
    window.destroy()


AUTH = {"username": "alice", "peer": "bob", "lab_mode": False,
        "own_fingerprint": "AAAA BBBB CCCC DDDD", "peer_key_found": True}


def test_validation_messages_for_every_field():
    assert validate_login_form("h", "5000", "alice", "bob", "pw") == {}
    errors = validate_login_form("h", "abc", "", "", "")
    assert set(errors) == {"port", "username", "peer", "password"}
    assert "number" in errors["port"]
    assert validate_login_form("h", "5000", "alice", "alice", "pw") == {"peer": "The peer must be someone else."}
    assert "port" in validate_login_form("h", "70000", "alice", "bob", "pw")
    assert "port" in validate_login_form("h", "0", "alice", "bob", "pw")
    assert validate_login_form("h", "", "alice", "bob", "pw") == {}  # empty port = default


def test_invalid_form_shows_inline_errors_and_never_connects(app):
    app._start_auth("login")
    app.update()
    for key in ("username", "peer", "password"):
        assert app._fields[key].error, key
        assert app._field_errors[key].winfo_ismapped(), key
        assert app._field_errors[key].cget("text")
    assert app.client is None and str(app.login_button.cget("state")) != "disabled"
    # fixing a field and retrying clears its error
    app.username_var.set("alice"); app.peer_var.set("bob"); app.password_var.set("x")
    app.port_var.set("nope")
    app._start_auth("login")
    app.update()
    assert not app._fields["username"].error
    assert app._fields["port"].error and app.server_box.winfo_ismapped(), \
        "an invalid port must open the server settings so the error is visible"


def test_enter_submits_when_all_fields_are_filled_otherwise_moves_on(app):
    calls = []
    app._start_auth = lambda mode: calls.append(mode)
    entries = [app._fields[k].entry for k in ("username", "peer", "password")]
    app.username_var.set("alice")
    entries[0].focus_set(); app.update()
    entries[0].event_generate("<Return>"); app.update()
    assert calls == [] and app.focus_get() is entries[1], "Enter should move to the next empty field"
    app.peer_var.set("bob"); app.password_var.set("pw")
    entries[1].event_generate("<Return>"); app.update()
    assert calls == ["login"], "Enter with every field filled must submit"


def test_show_hide_password_toggle(app):
    entry = app._fields["password"].entry
    assert entry.cget("show") == "•" and app._pw_toggle.cget("text") == "Show"
    app._toggle_password()
    assert entry.cget("show") == "" and app._pw_toggle.cget("text") == "Hide"
    app._toggle_password()
    assert entry.cget("show") == "•"


def test_progress_list_has_the_five_real_steps_and_fits_a_short_window(app):
    app.username_var.set("alice"); app.peer_var.set("bob"); app.password_var.set("pw")
    app.port_var.set("1")   # nothing listens there: the worker will fail, which is fine
    app._start_auth("login")
    app.update()
    texts = [row[2].cget("text") for row in app.steps._rows]
    assert texts == ["Connecting over TLS 1.3", "Verifying the server certificate", "Logging in",
                     "Exchanging keys with bob", "Verifying the handshake signature"]
    assert not app._fields["username"].winfo_ismapped(), "the form is hidden while connecting"
    card = app.login_frame.winfo_children()[0]
    assert card.winfo_reqheight() <= 540, "card with the progress list must fit a 540px window"


def test_steps_tick_off_from_real_events_in_any_order(app):
    app.steps.set_steps(["a", "b", "c", "d", "e"])
    app.username_var.set("alice")
    # events as a real connection delivers them
    app._handle_event("tls_cert_fingerprint", {"fingerprint": "8D5B 2639 BBAA 8F8C"})
    assert app.steps.state(0) == "pending", "the fingerprint alone does not prove the handshake"
    app._handle_event("tls_connected", {"version": "TLSv1.3"})
    assert app.steps.state(0) == "done" and app.steps.state(1) == "done"
    assert "TLS 1.3" in app.steps._rows[0][2].cget("text")
    assert "8D5B 2639 BBAA 8F8C" in app.steps._rows[1][2].cget("text")
    # the handshake can finish BEFORE auth_success is processed (second user to join)
    app._handle_event("handshake_established", {"peer": "bob"})
    app._handle_event("auth_success", dict(AUTH))
    assert [app.steps.state(i) for i in range(5)] == ["done"] * 5


def test_peer_offline_shows_waiting_then_chat_opens(app):
    app.steps.set_steps(["a", "b", "c", "d", "e"])
    app._handle_event("tls_connected", {"version": "TLSv1.3"})
    app._handle_event("auth_success", dict(AUTH, peer_key_found=False))
    assert app.steps.state(3) == "waiting"
    assert "Waiting for bob" in app.steps._rows[3][2].cget("text")
    app._handoff_to_chat()
    app.update()
    assert app.chat_frame.winfo_ismapped() and not app.login_frame.winfo_ismapped()


def test_events_before_the_chat_screen_are_buffered_and_replayed_in_order(app):
    app.steps.set_steps(["a", "b", "c", "d", "e"])
    app._handle_event("handshake_established", {"peer": "bob"})   # arrives early
    assert not app._chat_ready and len(app._held_events) == 1
    app._handle_event("auth_success", dict(AUTH))
    app._handoff_to_chat()
    app.update()
    assert app._chat_ready and app._held_events == []
    # replay ran AFTER the "pending" header was set, so the final state is secure
    assert "Secure session established" in app.session_status.cget("text")
    assert app.chip_e2e.kind == "ok"


def test_tls_failure_marks_the_first_step_red_and_back_restores_the_form(app):
    app.steps.set_steps(["Connecting over TLS 1.3", "b", "c", "d", "e"])
    app._set_login_busy(True)
    app._handle_event("auth_error", {"detail": "Could not connect to 127.0.0.1:1", "stage": "tls"})
    app.update()
    assert app.steps.state(0) == "error" and "Could not connect" in app.steps._rows[0][2].cget("text")
    assert app.back_button.winfo_ismapped()
    app._login_back()
    app.update()
    assert app._fields["username"].winfo_ismapped() and not app.steps.winfo_ismapped()
    assert str(app.login_button.cget("state")) != "disabled"
