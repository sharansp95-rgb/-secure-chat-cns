"""The security dashboard: KPI tiles, readable colour-coded feed, raw details on click, and
the Locked accounts list with a live countdown. All numbers come from the security-event
log only (the dashboard never talks to the server). Skipped where Tk has no display."""

import json
import time
import tkinter as tk

import pytest

import gui.security_dashboard as dashboard
from gui.explain import compute_kpis, countdown, describe_log_event, lock_records, locked_accounts

NOW = 1_800_000_000.0


def ev(event, **kw):
    return {"ts": NOW, "event": event, **kw}


# ---- pure logic -----------------------------------------------------------------------

@pytest.mark.parametrize("record,severity,needle", [
    (ev("user_registered", username="alice"), "info", "alice registered a new account"),
    (ev("user_login", username="alice"), "ok", "alice logged in"),
    (ev("failed_login", username="carol", from_addr="127.0.0.1"), "warn", "Failed login for carol"),
    (ev("account_locked", username="carol", retry_after=30, lock_level=0), "bad",
     "carol locked out for 30 s after repeated failed logins (lockout #1)"),
    (ev("lockout_rejected", username="carol", retry_after=12.4), "warn", "refused (12 s left)"),
    (ev("address_rate_limited", from_addr="10.0.0.9", attempted_type="login"), "warn", "10.0.0.9"),
    (ev("non_tls_connection", from_addr="10.0.0.9"), "warn", "not a TLS client"),
    (ev("malformed_envelope", from_user="bob"), "warn", "Malformed message from bob"),
    (ev("lab_control_rejected", requested_by="alice", reason="lab mode is off"), "warn", "lab mode is off"),
    (ev("lab_attack_performed", action="tamper_next", target="alice", armed_by="alice"), "warn",
     "Relay attack performed: tampering with a message on alice's traffic (armed by alice)"),
    (ev("security_alert", reported_by="bob", alert="message_rejected", reason="decryption_failed",
        peer="alice"), "bad",
     "bob's client blocked a message from alice: tampered in transit (caught by AES-256-GCM "
     "authentication tag)"),
    (ev("security_alert", reported_by="bob", alert="handshake_aborted", reason="x", peer="alice"),
     "bad", "refused a tampered key exchange"),
])
def test_events_get_readable_one_line_descriptions(record, severity, needle):
    glyph, sev, text = describe_log_event(record)
    assert glyph and sev == severity and needle in text
    assert "=" not in text.split("(")[0] or record["event"] in ("lab_control_rejected",), \
        "descriptions are sentences, not key=value dumps"


def test_unknown_events_still_get_a_line():
    _g, sev, text = describe_log_event(ev("something_new", detail="x"))
    assert sev == "info" and "something_new" in text


def test_kpis_come_from_the_log_records_only():
    events = [ev("user_registered", username="a"), ev("user_login", username="b"),
              ev("user_login", username="a"), ev("failed_login", username="c"),
              ev("failed_login", username="c"), ev("security_alert", reported_by="b"),
              ev("lab_attack_performed")]
    assert compute_kpis(events) == {"attacks_detected": 1, "failed_logins": 2, "active_users": 2}
    assert compute_kpis([]) == {"attacks_detected": 0, "failed_logins": 0, "active_users": 0}


def test_locked_accounts_expire_and_a_login_clears_them_early():
    events = [ev("account_locked", username="carol", retry_after=60, lock_level=1),
              ev("account_locked", username="dave", retry_after=60, lock_level=0),
              dict(ev("user_login", username="dave"), ts=NOW + 5)]
    active = locked_accounts(events, NOW + 10)
    assert set(active) == {"carol"} and round(active["carol"]["remaining"]) == 50
    assert locked_accounts(events, NOW + 61) == {}, "the lock has run out"
    assert set(lock_records(events)) == {"carol"}


def test_countdown_format():
    assert countdown(42) == "0:42" and countdown(125) == "2:05" and countdown(-3) == "0:00"


# ---- the window -----------------------------------------------------------------------

def write(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


@pytest.fixture()
def make(tmp_path):
    windows = []

    def factory(records=(), geometry="920x620+10000+10000"):
        log = tmp_path / "events.jsonl"
        write(log, records)
        try:
            window = dashboard.SecurityDashboard(log_path=str(log))
        except tk.TclError as exc:
            pytest.skip(f"no display available for Tk: {exc}")
        windows.append(window)
        window.geometry(geometry)
        window.update()
        return window, log

    yield factory
    for window in windows:
        window.update()
        window.destroy()


def tile(window, key):
    return window._tiles[key][1].cget("text")


def feed(window):
    return window.feed_text.get("1.0", "end")


def test_tiles_show_the_numbers_and_the_feed_shows_sentences(make):
    now = time.time()
    window, _ = make([
        {"ts": now, "event": "user_registered", "username": "alice"},
        {"ts": now, "event": "failed_login", "username": "carol", "from_addr": "127.0.0.1"},
        {"ts": now, "event": "security_alert", "reported_by": "bob", "alert": "message_rejected",
         "reason": "decryption_failed", "peer": "alice"},
    ])
    assert (tile(window, "attacks_detected"), tile(window, "failed_logins"),
            tile(window, "active_users")) == ("1", "1", "1")
    text = feed(window)
    assert "alice registered a new account" in text and "Failed login for carol" in text
    assert "from_addr=" not in text, "raw key=value strings are not shown in the feed"


def test_a_tile_flashes_when_its_value_changes(make):
    window, log = make([ev("failed_login", username="x", ts=time.time())])
    failed_tile = window._tiles["failed_logins"][0]
    base = failed_tile.cget("highlightbackground")
    with open(log, "a") as f:
        f.write(json.dumps({"ts": time.time(), "event": "failed_login", "username": "x"}) + "\n")
    window._signature = None            # force the next poll to re-read
    window._poll()
    window.update()
    assert tile(window, "failed_logins") == "2"
    assert failed_tile.cget("highlightbackground") != base


def test_clicking_a_feed_row_shows_its_raw_details(make):
    window, _ = make([{"ts": time.time(), "event": "failed_login", "username": "carol",
                       "from_addr": "127.0.0.1"}])
    assert window.detail_var.get() == ""
    window._show_details(1)
    assert "event=failed_login" in window.detail_var.get() and "username=carol" in window.detail_var.get()
    # and a real click on the row does the same
    # the row really is clickable: its tag carries a <Button-1> binding
    assert window.feed_text.tk.call(str(window.feed_text), "tag", "bind", "row1", "<Button-1>")


def test_locked_account_shows_a_live_countdown(make, monkeypatch):
    now = time.time()
    window, _ = make([{"ts": now - 10, "event": "account_locked", "username": "carol",
                       "retry_after": 60, "lock_level": 1}])
    window._tick()
    labels = [w.cget("text") for row in window.locked_list.winfo_children()
              for w in row.winfo_children() if isinstance(w, tk.Label)]
    assert "carol" in labels
    first = [x for x in labels if x.startswith("0:")][0]
    assert first in ("0:50", "0:49")
    assert tile(window, "locked_accounts") == "1"
    # five seconds later the same lock reads lower
    monkeypatch.setattr(time, "time", lambda: now + 5)
    window._tick()
    labels = [w.cget("text") for row in window.locked_list.winfo_children()
              for w in row.winfo_children() if isinstance(w, tk.Label)]
    later = [x for x in labels if x.startswith("0:")][0]
    assert int(later[2:]) < int(first[2:])


def test_no_locked_accounts_message_when_the_lock_has_expired(make):
    window, _ = make([{"ts": time.time() - 100, "event": "account_locked", "username": "carol",
                       "retry_after": 30, "lock_level": 0}])
    window._tick()
    assert window.locked_empty_label.winfo_exists() and tile(window, "locked_accounts") == "0"


def test_short_window_goes_compact_and_the_feed_keeps_its_room(make):
    window, _ = make([ev("user_login", username="alice", ts=time.time())],
                     geometry="1000x330+10000+10000")
    window.update()
    assert window._compact and not window._subtitle.winfo_ismapped()
    assert window.feed_text.winfo_height() >= 70, window.feed_text.winfo_height()
    window.geometry("1000x620+10000+10000")
    window.update()
    assert not window._compact and window._subtitle.winfo_ismapped()


def test_tiles_and_panes_fit_the_launcher_width(make):
    window, _ = make([], geometry="700x430+10000+10000")
    assert window.kpi_row.winfo_reqwidth() <= 700
    assert all(tile_frame.winfo_width() > 120 for tile_frame, _n in window._tiles.values())
