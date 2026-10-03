"""The Attack Lab panel: one card per attack, with the expected defence, and a live result
that comes from the VICTIM's own report of a real detection (read from the security log).

Presentation only: nothing here fires or detects an attack. The relay attacks are armed by
the server (see tests/test_attack_lab.py) and caught by the receiving client's real checks;
the card only displays a `security_alert` record that client sent. Skipped where Tk has no
display."""

import json
import threading
import time
import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
from gui.explain import (
    HANDSHAKE_SIGNATURE,
    LAB_ATTACKS,
    REJECTIONS,
    find_lab_detection,
    lab_status,
)
from gui.theme import is_no_display_error

# ---- pure logic -----------------------------------------------------------------------


def test_four_attacks_in_demo_order_each_with_an_expected_defence():
    assert [a["action"] for a in LAB_ATTACKS] == [
        "tamper_next", "replay_last", "drop_next", "mitm_next_handshake"]
    for a in LAB_ATTACKS:
        assert a["glyph"] and a["desc"] and a["check"] and a["label"] and a["title"]
    checks = {a["action"]: a["check"] for a in LAB_ATTACKS}
    assert checks["tamper_next"] == REJECTIONS["decryption_failed"]["check"]
    assert checks["replay_last"] == REJECTIONS["replay_duplicate"]["check"]
    assert checks["drop_next"] == REJECTIONS["chain_gap"]["check"]
    assert checks["mitm_next_handshake"] == HANDSHAKE_SIGNATURE["check"]


def alert(**kw):
    base = {"event": "security_alert", "reported_by": "bob", "ts": 1000.0,
            "alert": "message_rejected", "reason": "decryption_failed"}
    return {**base, **kw}


@pytest.mark.parametrize("action,event", [
    ("tamper_next", alert()),
    ("replay_last", alert(reason="replay_duplicate")),
    ("drop_next", alert(alert="chain_warning", reason="chain_gap")),
    ("mitm_next_handshake", alert(alert="handshake_aborted", reason="any long reason text")),
])
def test_detection_matches_the_victims_own_report(action, event):
    assert find_lab_detection(action, [event], "bob", 999.0) == event


@pytest.mark.parametrize("event", [
    alert(reported_by="alice"),                 # the attacker's own report is not the victim's
    alert(ts=900.0),                            # before the attack fired
    alert(reason="replay_duplicate"),           # a different check fired
    alert(alert="chain_warning"),               # a different kind of alert
    {"event": "lab_attack_performed", "ts": 1000.0},   # not a detection at all
])
def test_unrelated_records_are_not_detections(event):
    assert find_lab_detection("tamper_next", [event], "bob", 999.0) is None


def test_status_wording_for_every_state():
    assert lab_status("idle", "tamper_next", "bob") == ("off", "Not armed")
    assert lab_status("arming", "tamper_next", "bob")[0] == "warn"
    assert "send a message" in lab_status("armed", "tamper_next", "bob")[1]
    assert lab_status("fired", "tamper_next", "bob") == ("warn", "Fired. Waiting for bob's check...")
    assert lab_status("caught", "tamper_next", "bob") == (
        "ok", "Caught by AES-256-GCM authentication tag (reported by bob)")
    kind, text = lab_status("silent", "tamper_next", "bob")
    assert kind == "warn" and "No report from bob yet" in text and "Watch bob's window" in text
    assert lab_status("rejected", "tamper_next", "bob", "lab mode is off") == (
        "bad", "Rejected: lab mode is off")


# ---- the window -----------------------------------------------------------------------


class FakeClient:
    lab_mode = True
    username = "alice"
    peer = "bob"

    def __init__(self):
        self.armed = []
        self.stop_event = threading.Event()

    def send_lab_control(self, action, target=None):
        self.armed.append(action)


@pytest.fixture()
def app(tmp_path):
    try:
        window = chat_gui.ChatGUI(log_path=str(tmp_path / "events.jsonl"))
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip(f"no display available for Tk: {exc}")
        raise
    window.geometry("1040x660+10000+10000")
    window.update()
    window.client = FakeClient()
    window.username, window.peer = "alice", "bob"
    window._show_chat_screen()          # events are applied live once the chat screen is up
    yield window
    window.update()
    for child in window.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()
    window.update()
    window.destroy()


def lab_texts(app):
    out = []

    def walk(widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                out.append(str(child.cget("text")))
            walk(child)
    walk(app._lab_window)
    return "\n".join(out)


def test_panel_has_the_lab_mode_banner_and_one_card_per_attack(app):
    app._open_attack_lab()
    app.update()
    text = lab_texts(app)
    assert "LAB MODE: relay is acting maliciously on request" in text
    assert "one-shot" in text
    for a in LAB_ATTACKS:
        assert a["title"] in text and a["desc"] in text and a["check"] in text
    assert text.count("Expected defence") == 4
    assert len(app._lab_cards) == 4
    assert app._lab_window.title() == "Attack Lab"


def test_panel_only_opens_in_lab_mode(app):
    app.client.lab_mode = False
    app._open_attack_lab()
    assert not app._lab_window_alive()


def test_opening_twice_reuses_the_same_window(app):
    app._open_attack_lab()
    first = app._lab_window
    app._open_attack_lab()
    assert app._lab_window is first
    assert len([c for c in app.winfo_children() if isinstance(c, tk.Toplevel)]) == 1


def test_arm_buttons_send_the_matching_action_and_show_arming(app):
    app._open_attack_lab()
    for attack in LAB_ATTACKS:
        card = app._lab_cards[attack["action"]]
        assert card["button"].cget("text") == attack["label"]
        card["button"].invoke()
    deadline = time.time() + 3
    while len(app.client.armed) < 4 and time.time() < deadline:
        time.sleep(0.01)
    assert sorted(app.client.armed) == sorted(a["action"] for a in LAB_ATTACKS)
    assert app._lab_cards["tamper_next"]["chip"].cget("text") == "Arming..."


def test_server_replies_drive_the_card_state(app):
    app._open_attack_lab()
    app._handle_event("lab_control_result", {"action": "tamper_next", "armed": True,
                                             "detail": "armed"})
    chip = app._lab_cards["tamper_next"]["chip"]
    assert chip.cget("text") == "Armed: send a message now" and chip.kind == "warn"
    app._handle_event("lab_control_result", {"action": "drop_next", "armed": False,
                                             "detail": "lab mode is off"})
    drop = app._lab_cards["drop_next"]["chip"]
    assert drop.cget("text") == "Rejected: lab mode is off" and drop.kind == "bad"


def test_card_turns_green_only_when_the_victims_report_is_in_the_log(app, tmp_path):
    app._open_attack_lab()
    app._handle_event("lab_attack_performed", {"action": "tamper_next",
                                               "detail": "flipped a byte in alice's next message"})
    chip = app._lab_cards["tamper_next"]["chip"]
    assert chip.cget("text") == "Fired. Waiting for bob's check..." and chip.kind == "warn"
    log = tmp_path / "events.jsonl"
    now = time.time()
    # records that must NOT count: wrong reporter, wrong check, and one logged before the attack
    log.write_text("\n".join(json.dumps(r) for r in [
        alert(reported_by="alice", ts=now + 1), alert(reason="replay_duplicate", ts=now + 1),
        alert(ts=now - 60)]) + "\n")
    app._poll_lab_detection()
    assert app._lab_state["tamper_next"]["state"] == "fired"
    with open(log, "a") as f:
        f.write(json.dumps(alert(ts=time.time())) + "\n")
    app._poll_lab_detection()
    app.update()
    assert chip.cget("text") == "Caught by AES-256-GCM authentication tag (reported by bob)"
    assert chip.kind == "ok"


def test_without_a_report_the_card_says_so_instead_of_claiming_anything(app):
    app._open_attack_lab()
    app._handle_event("lab_attack_performed", {"action": "replay_last", "detail": "resent"})
    app._lab_state["replay_last"]["fired_at"] = time.time() - 30
    app._poll_lab_detection()
    chip = app._lab_cards["replay_last"]["chip"]
    assert "No report from bob yet" in chip.cget("text") and chip.kind == "warn"
    # and it keeps listening: a late report still turns it green
    with open(app.log_path, "w") as f:
        f.write(json.dumps(alert(reason="replay_duplicate", ts=time.time())) + "\n")
    app._poll_lab_detection()
    assert chip.kind == "ok"


def test_state_survives_closing_and_reopening_the_panel(app):
    app._open_attack_lab()
    app._handle_event("lab_control_result", {"action": "drop_next", "armed": True, "detail": "x"})
    app._lab_window.destroy()
    app.update()
    app._open_attack_lab()
    assert app._lab_cards["drop_next"]["chip"].kind == "warn"
    assert "Armed" in app._lab_cards["drop_next"]["chip"].cget("text")


def test_panel_fits_a_laptop_screen_and_escape_closes_it(app):
    app._open_attack_lab()
    app.update()
    win = app._lab_window
    assert win.winfo_reqheight() <= 640 and win.winfo_reqwidth() <= 780, (
        win.winfo_reqwidth(), win.winfo_reqheight())
    win.event_generate("<Escape>")
    app.update()
    assert not app._lab_window_alive()
