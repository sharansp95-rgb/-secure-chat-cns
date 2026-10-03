"""The security receipt: green check rows, truncated mono values with a Copy button for the
FULL value, and a plain-English verdict. The wording comes from gui/explain.py (pure); the
receipt data was produced by the client's real checks before the message was ever shown.
Skipped where Tk has no display."""

import tkinter as tk
import time

import pytest

import gui.chat_gui as chat_gui
from gui.explain import receipt_details, receipt_rows, receipt_summary, shorten
from gui.theme import is_no_display_error

FULL_HASH = "48564a5d663e0cbc9219" + "ab" * 22
RECEIVED = {"direction": "received", "sender": "bob", "sender_fingerprint": "8860 7244 2628 167C",
            "timestamp": time.time() - 3, "age_seconds": 3, "seq": 4, "prev_hash": FULL_HASH,
            "chain_link": "ok", "record_hash": "5a272dd5f346a49abb63" + "cd" * 22,
            "nonce": "5tOzW6a7fjDqbr7AAAAAAAAA"}
SENT = {"direction": "sent", "sender": "alice", "sender_fingerprint": "6B7A C666 FCF7 6CF5",
        "timestamp": time.time(), "seq": 1, "prev_hash": FULL_HASH, "record_hash": "ab" * 32,
        "nonce": "NNNN"}


# ---- pure wording -----------------------------------------------------------------------

def test_received_receipt_has_four_green_rows_and_the_spec_sentence():
    rows = receipt_rows(RECEIVED)
    assert [r[0] for r in rows] == ["ok"] * 4
    titles = [r[1] for r in rows]
    assert titles == ["Not tampered with", "Really from bob", "Fresh", "In order"]
    assert "authentication tag" in rows[0][2] and "RSA signature" in rows[1][2]
    assert "3 s" in rows[2][2] and "#4" in rows[3][2]
    assert receipt_summary(RECEIVED) == (
        "ok", "This message is authentic, unmodified, fresh, and in order.")


def test_a_chain_gap_is_amber_and_the_sentence_does_not_say_in_order():
    gap = dict(RECEIVED, chain_link="gap")
    rows = receipt_rows(gap)
    assert rows[-1][0] == "warn" and rows[-1][1] == "Earlier message missing"
    kind, sentence = receipt_summary(gap)
    assert kind == "warn" and "in order" not in sentence and "missing" in sentence


def test_sent_receipt_describes_signing_encryption_and_chaining():
    assert [r[1] for r in receipt_rows(SENT)] == ["Signed by you", "Encrypted", "Chained"]
    kind, sentence = receipt_summary(SENT)
    assert kind == "ok" and "signed" in sentence and "chained" in sentence


def test_details_carry_the_full_values_and_shorten_truncates_for_display():
    details = {label: (value, mono) for label, value, mono in receipt_details(RECEIVED)}
    assert details["prev_hash"] == (FULL_HASH, True)
    assert details["Nonce"][1] and details["Record SHA-256"][1]
    assert details["Sender"][1] is False and "8860 7244 2628 167C" in details["Sender"][0]
    assert shorten(FULL_HASH).endswith("…") and len(shorten(FULL_HASH)) == 23
    assert shorten("short") == "short" and shorten(None) == "-"


# ---- the window -----------------------------------------------------------------------

@pytest.fixture()
def app():
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    window.geometry("1040x660+10000+10000")
    window.update()
    yield window
    window.update()
    for child in window.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()
    window.update()
    window.destroy()


def texts(win):
    out = []

    def walk(widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                out.append(str(child.cget("text")))
            walk(child)
    walk(win)
    return "\n".join(out)


def copy_buttons(win):
    found = []

    def walk(widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Label) and str(child.cget("text")) == "Copy":
                found.append(child)
            walk(child)
    walk(win)
    return found


def test_receipt_window_shows_rows_values_and_verdict(app):
    win = app._show_receipt(RECEIVED)
    app.update()
    text = texts(win)
    for needle in ("Security receipt", "Message you received from bob", "Not tampered with",
                   "Really from bob", "Fresh", "In order",
                   "This message is authentic, unmodified, fresh, and in order."):
        assert needle in text, needle
    assert FULL_HASH not in text, "long hashes are truncated on screen"
    assert shorten(FULL_HASH) in text
    assert win.title() == "Security receipt"


def test_copy_button_copies_the_full_untruncated_value(app):
    win = app._show_receipt(RECEIVED)
    app.update()
    buttons = copy_buttons(win)
    assert len(buttons) == 3, "nonce, prev_hash and record hash each get a Copy button"
    copied = []
    for button in buttons:
        button.event_generate("<Button-1>")
        app.update()
        copied.append(app.clipboard_get())
        assert button.cget("text") == "Copied ✓"
    assert RECEIVED["nonce"] in copied and FULL_HASH in copied and RECEIVED["record_hash"] in copied


def test_sent_receipt_window_has_the_sent_rows_and_sentence(app):
    win = app._show_receipt(SENT)
    app.update()
    text = texts(win)
    assert "Message you sent" in text and "Signed by you" in text and "Encrypted" in text
    assert "Your peer's client verifies it when it arrives." in text


def test_gap_receipt_window_is_flagged_amber(app):
    win = app._show_receipt(dict(RECEIVED, chain_link="gap"))
    app.update()
    text = texts(win)
    assert "Earlier message missing" in text and "authentic and unmodified, but earlier" in text


def test_receipt_fits_the_screen_and_escape_closes_it(app):
    win = app._show_receipt(RECEIVED)
    app.update()
    assert win.winfo_reqheight() <= 640 and win.winfo_reqwidth() <= 560, (
        win.winfo_reqwidth(), win.winfo_reqheight())
    win.event_generate("<Escape>")
    app.update()
    assert not win.winfo_exists()


def test_clicking_a_bubble_opens_the_receipt(app):
    app.username, app.peer = "alice", "bob"
    app._handle_event("auth_success", {"username": "alice", "peer": "bob", "lab_mode": False,
                                       "own_fingerprint": None, "peer_key_found": True})
    app._handoff_to_chat()
    app._handle_event("message_received", {"sender": "bob", "message": "hi", "timestamp": time.time(),
                                          "receipt": RECEIVED})
    app.update()
    bubble = [c for r in app.bubble_list.winfo_children() for c in r.winfo_children()
              if isinstance(c, tk.Canvas) and c.bind("<Button-1>")][0]
    bubble.event_generate("<Button-1>", x=8, y=8)
    app.update()
    assert any(isinstance(c, tk.Toplevel) and c.title() == "Security receipt"
               for c in app.winfo_children())
