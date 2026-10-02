"""The "What just happened?" banners: plain-English wording (gui/explain.py, no Tk needed)
and the banner strip in the chat window. A banner appears ONLY for an event a real check
or the real session produced; nothing here decides whether something is secure."""

import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
from gui.explain import banner_for

AUTH = {"username": "alice", "peer": "bob", "lab_mode": True,
        "own_fingerprint": "AAAA BBBB CCCC DDDD", "peer_key_found": True}


# ---- wording (pure) ----------------------------------------------------------------

@pytest.mark.parametrize("kind,data,severity,text", [
    ("handshake_established", {"peer": "bob"}, "ok",
     "Keys were exchanged with ECDH and the exchange was signed with RSA. The server never saw the key."),
    ("message_rejected", {"reason": "decryption_failed"}, "bad",
     "The relay changed one byte. AES-GCM's authentication tag no longer matched, so the message was rejected."),
    ("message_rejected", {"reason": "replay_duplicate"}, "bad",
     "An old message was sent again. The duplicate nonce/timestamp check rejected it."),
    ("chain_warning", {"reason": "chain_gap"}, "warn",
     "A message is missing. The hash chain noticed the gap in the sequence."),
    ("handshake_aborted", {"reason": "the ECDH public key ... did NOT verify against their RSA public key"}, "bad",
     "Someone swapped the key during the handshake. The RSA signature check failed, so no session was created."),
    ("evidence_exported", {}, "ok",
     "A signed copy of this conversation was saved. Anyone can verify it offline."),
])
def test_banner_wording_matches_the_spec(kind, data, severity, text):
    assert banner_for(kind, data) == (severity, text)


def test_other_rejections_fall_back_to_their_explanation_and_unknown_events_have_none():
    sev, text = banner_for("message_rejected", {"reason": "malformed"})
    assert sev == "bad" and text
    assert banner_for("message_received", {}) is None
    assert banner_for("envelope_sent", {}) is None
    assert banner_for("message_rejected", {"reason": "never-heard-of-it"}) is None


def test_banners_are_one_or_two_sentences():
    from gui.explain import BANNER_TEXT
    for key, (_sev, text) in BANNER_TEXT.items():
        assert 1 <= text.count(". ") + 1 <= 2, key
        assert len(text) < 200, key


# ---- the banner strip (needs Tk) ------------------------------------------------------

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


def banner_text(app):
    return app.banner_label.cget("text") if app._banner is not None else None


def test_no_banner_until_something_happens(app):
    assert app._banner is None
    app._handle_event("message_received", {"sender": "bob", "message": "hi", "timestamp": 1,
                                           "receipt": {}})
    assert app._banner is None, "ordinary messages must not produce banners"


def test_session_established_shows_the_ecdh_rsa_banner(app):
    app._handle_event("handshake_established", {"peer": "bob"})
    app.update()
    assert "ECDH" in banner_text(app) and "never saw the key" in banner_text(app)


def test_a_rejection_banner_follows_the_real_event_and_replaces_the_previous_one(app):
    app._handle_event("handshake_established", {"peer": "bob"})
    app._handle_event("message_rejected", {"sender": "bob", "reason": "decryption_failed",
                                           "detail": "x"})
    app.update()
    assert "authentication tag" in banner_text(app)
    assert len(app.banner_holder.winfo_children()) == 1, "a new banner replaces the old one"
    app._handle_event("chain_warning", {"sender": "bob", "reason": "chain_gap", "detail": "x"})
    assert "hash chain noticed the gap" in banner_text(app)


def test_banner_can_be_dismissed(app):
    app._handle_event("handshake_established", {"peer": "bob"})
    app.update()
    close = [w for w in app._banner[0].winfo_children() if isinstance(w, tk.Label)][0]
    close.event_generate("<Button-1>")
    app.update()
    assert app._banner is None and not app.banner_holder.winfo_children()


def test_explain_events_toggle_turns_banners_off(app):
    app._handle_event("handshake_established", {"peer": "bob"})
    app.explain_var.set(False)
    app._on_explain_toggled()
    assert app._banner is None, "turning it off dismisses the current banner"
    app._handle_event("message_rejected", {"sender": "bob", "reason": "replay_duplicate",
                                           "detail": "x"})
    assert app._banner is None
    # ...but the blocked card in the conversation is still drawn (that is not an "explanation")
    assert any(i["kind"] == "blocked" for i in app._items)
    app.explain_var.set(True)
    app._handle_event("message_rejected", {"sender": "bob", "reason": "replay_duplicate",
                                           "detail": "x"})
    assert "duplicate nonce" in banner_text(app)


def test_settings_menu_has_the_explain_toggle_and_is_on_by_default(app):
    assert app.explain_var.get() is True
    labels = [app.settings_menu.entrycget(i, "label") for i in range(app.settings_menu.index("end") + 1)]
    assert "Explain events" in labels


def test_attacker_window_gets_an_info_banner_without_claiming_detection(app):
    app._handle_event("lab_attack_performed", {"detail": "flipped a byte in alice's next chat "
                                                         "message's ciphertext", "action": "tamper_next"})
    app.update()
    text = banner_text(app)
    assert "their own checks decide" in text and "caught" in text.lower()
    assert "was caught" not in text and "detected" not in text


def test_banner_wraps_within_a_narrow_window(app):
    app.geometry("720x560+10000+10000")
    app.update()
    app._handle_event("handshake_aborted", {"peer": "bob", "reason": "did NOT verify against"})
    app.update()
    assert int(str(app.banner_label.cget("wraplength"))) <= app.winfo_width()
    assert app.banner_label.winfo_reqwidth() <= app.winfo_width()
