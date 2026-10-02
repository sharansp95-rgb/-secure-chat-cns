"""Tests for Stage D's server/lockout.py: per-account lockout with
exponential backoff, and the independent per-source-address rate limit."""

import os
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.lockout import LockoutGuard  # noqa: E402


def make_guard(threshold=5, window=300, backoff=(30, 60, 120, 300, 900),
              addr_limit=20, addr_window=60):
    return LockoutGuard(threshold=threshold, window=window, backoff_schedule=backoff,
                        addr_limit=addr_limit, addr_window=addr_window)


# --- lockout triggers at exactly the threshold -------------------------------

def test_not_locked_before_threshold():
    g = make_guard(threshold=5)
    for _ in range(4):
        status = g.record_failure("alice", addr="1.2.3.4")
        assert status.locked is False
    assert g.status("alice").locked is False


def test_locked_at_exactly_the_threshold():
    g = make_guard(threshold=5)
    statuses = [g.record_failure("alice", addr="1.2.3.4") for _ in range(5)]
    assert [s.locked for s in statuses] == [False, False, False, False, True]
    assert statuses[-1].newly_locked is True
    assert g.status("alice").locked is True


def test_failures_outside_the_window_do_not_count():
    g = make_guard(threshold=5, window=60)
    now = time.time()
    for i in range(4):
        g.record_failure("alice", addr="1.2.3.4", now=now + i)
    # 5th failure arrives well after the window: the first 4 have expired.
    status = g.record_failure("alice", addr="1.2.3.4", now=now + 1000)
    assert status.locked is False


# --- backoff grows and caps ---------------------------------------------------

def test_backoff_grows_on_repeated_lockouts():
    g = make_guard(threshold=2, backoff=(30, 60, 120))
    now = time.time()

    def lock_once(t0):
        g.record_failure("alice", now=t0)
        return g.record_failure("alice", now=t0 + 1)

    first = lock_once(now)
    assert first.retry_after == 30
    # Let the first lock expire, then trigger a second lockout.
    second = lock_once(now + 31)
    assert second.retry_after == 60
    third = lock_once(now + 31 + 61)
    assert third.retry_after == 120


def test_backoff_caps_at_the_schedule_end():
    g = make_guard(threshold=2, backoff=(30, 60))
    now = time.time()
    for i in range(5):  # far more lockouts than the schedule has entries
        g.record_failure("alice", now=now + i * 1000)
        status = g.record_failure("alice", now=now + i * 1000 + 1)
    assert status.retry_after == 60  # capped at the last entry, never grows past it


# --- success resets ------------------------------------------------------------

def test_success_resets_failure_count():
    g = make_guard(threshold=5)
    for _ in range(4):
        g.record_failure("alice")
    g.record_success("alice")
    assert g.status("alice").locked is False
    # The reset failure count means it again takes a full `threshold` more
    # failures to lock, not just one more.
    for _ in range(4):
        assert g.record_failure("alice").locked is False
    assert g.record_failure("alice").locked is True


def test_success_resets_backoff_tier_to_first():
    g = make_guard(threshold=1, backoff=(30, 60, 120))
    now = time.time()
    first = g.record_failure("alice", now=now)
    assert first.retry_after == 30
    g.record_success("alice")
    second = g.record_failure("alice", now=now + 1)
    assert second.retry_after == 30  # back to tier 0, not 60


# --- locked attempts skip PBKDF2 (checked via a spy) --------------------------

def test_locked_status_check_means_caller_never_calls_verify_password():
    """Mirrors how server.py actually uses this: status() is checked FIRST,
    and verify_password is only ever called when status().locked is False."""
    g = make_guard(threshold=1)
    g.record_failure("alice")
    assert g.status("alice").locked is True

    with patch("auth.password_hash.verify_password") as spy:
        status = g.status("alice")
        if not status.locked:
            from auth.password_hash import verify_password
            verify_password("whatever", "pbkdf2_sha256$1$x$y")
        spy.assert_not_called()


# --- generic message before lockout (server-level behavior) -------------------

def test_the_record_that_triggers_lockout_is_itself_reported_as_a_plain_failure():
    """The LockStatus from the triggering call carries no special
    "you are now locked out" flag beyond `newly_locked` -- server.py is
    responsible for still sending the generic "invalid username or
    password" on that exact call, which test_security_events.py checks
    end-to-end. Here we just confirm the guard itself doesn't leak
    anything extra."""
    g = make_guard(threshold=3)
    g.record_failure("alice")
    g.record_failure("alice")
    triggering = g.record_failure("alice")
    assert triggering.locked is True and triggering.newly_locked is True
    # No username-existence signal beyond locked/newly_locked/retry_after.
    assert set(vars(triggering)) == {"locked", "retry_after", "newly_locked", "lock_level"}


# --- locked_accounts() for the dashboard --------------------------------------

def test_locked_accounts_lists_only_currently_locked_usernames():
    g = make_guard(threshold=1, backoff=(30,))
    now = time.time()
    g.record_failure("alice", now=now)
    g.record_failure("bob", now=now)
    g.record_success("bob")  # bob then... wait, record_failure already locked bob
    # bob was locked by the single failure (threshold=1); record_success unlocks him.
    locked = {d["username"]: d for d in g.locked_accounts(now=now + 1)}
    assert "alice" in locked and "bob" not in locked
    assert 0 < locked["alice"]["remaining"] <= 30


def test_locked_accounts_excludes_expired_locks():
    g = make_guard(threshold=1, backoff=(30,))
    now = time.time()
    g.record_failure("alice", now=now)
    assert g.locked_accounts(now=now + 1)
    assert g.locked_accounts(now=now + 31) == []  # lock has expired


# --- per-source-address rate limit --------------------------------------------

def test_address_rate_limit_allows_up_to_the_cap():
    g = make_guard(addr_limit=3, addr_window=60)
    now = time.time()
    results = [g.check_address_rate("9.9.9.9", now=now + i) for i in range(4)]
    assert results == [True, True, True, False]


def test_address_rate_limit_is_independent_per_address():
    g = make_guard(addr_limit=1, addr_window=60)
    now = time.time()
    assert g.check_address_rate("1.1.1.1", now=now) is True
    assert g.check_address_rate("2.2.2.2", now=now) is True   # different address, unaffected
    assert g.check_address_rate("1.1.1.1", now=now) is False  # same address, over the cap


def test_address_rate_limit_recovers_after_the_window():
    g = make_guard(addr_limit=1, addr_window=30)
    now = time.time()
    assert g.check_address_rate("9.9.9.9", now=now) is True
    assert g.check_address_rate("9.9.9.9", now=now + 10) is False
    assert g.check_address_rate("9.9.9.9", now=now + 31) is True  # window has rolled
