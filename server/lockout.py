"""Login lockout / rate limiting (Stage D).

Two independent mechanisms:

1. **Per-account lockout with exponential backoff.** Each failed login is
   tracked per username (with the source address recorded alongside it, for
   forensics -- see `account_locked` event logging in server.py). Once a
   username accumulates `threshold` failures within `window` seconds, it is
   locked: further login attempts for that username are rejected *without
   running PBKDF2* (`LockStatus.locked`, checked by the caller *before* it
   ever calls `auth.password_hash.verify_password`) -- this matters because
   PBKDF2 is deliberately slow (200,000 iterations, see
   auth/password_hash.py), so verifying it on every one of an attacker's
   repeated guesses against a locked account would itself be a CPU-exhaustion
   opening. A successful login resets the account's failure count and lock
   level to zero. Lock duration follows `backoff_schedule` and grows each
   time the account is locked again after a previous lock has expired
   (e.g. 30s, then 60s, then 120s, ... capped at the schedule's last entry),
   reset back to the first tier by a successful login.

   **Enumeration trade-off (deliberate, documented here because it's easy to
   get backwards):** every rejection for a *not-yet-locked* account says the
   same generic "invalid username or password" — including the exact
   failure that pushes the account over the threshold — so an attacker
   cannot distinguish "wrong password for a real account" from "no such
   account" by timing or wording alone. Only once an account is *already*
   locked does a login attempt get the more specific "account temporarily
   locked" message; by then the attacker already knows the account exists
   (they have been guessing against it long enough to lock it), so this
   message leaks nothing a patient attacker couldn't already infer from the
   lockout itself, and the lockout message is genuinely useful to the real
   owner of the account.

2. **Per-source-address rate limiting**, independent of any one username:
   `check_address_rate` caps how many register+login *attempts* (successful
   or not) one source address may make in a sliding window, to slow
   scripted abuse that spreads guesses across many different usernames
   rather than hammering one account (which mechanism 1 alone would not
   catch, since no single username would ever reach its own threshold).
"""

import threading
import time
from dataclasses import dataclass, field

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300          # failures must fall within this window to count
DEFAULT_BACKOFF_SCHEDULE = (30, 60, 120, 300, 900)   # seconds; last entry is the cap (15 min)
DEFAULT_ADDR_LIMIT = 20
DEFAULT_ADDR_WINDOW_SECONDS = 60


@dataclass
class LockStatus:
    locked: bool
    retry_after: float = 0.0       # seconds remaining, if locked
    newly_locked: bool = False     # True only on the record_failure() call that triggered it
    lock_level: int = 0            # which backoff tier was used (0-indexed)


@dataclass
class _UserState:
    failures: list = field(default_factory=list)   # [(timestamp, addr), ...]
    lock_level: int = 0
    locked_until: float = 0.0


class LockoutGuard:
    """Thread-safe, in-memory (per server process) lockout + rate limiter.
    Deliberately not persisted to disk: a server restart clearing lockouts
    is an acceptable, documented trade-off for a course project's single
    relay server (see README's "Known limitations")."""

    def __init__(self, threshold=DEFAULT_THRESHOLD, window=DEFAULT_WINDOW_SECONDS,
                 backoff_schedule=DEFAULT_BACKOFF_SCHEDULE,
                 addr_limit=DEFAULT_ADDR_LIMIT, addr_window=DEFAULT_ADDR_WINDOW_SECONDS):
        self.threshold = threshold
        self.window = window
        self.backoff_schedule = tuple(backoff_schedule)
        self.addr_limit = addr_limit
        self.addr_window = addr_window
        self._lock = threading.Lock()
        self._by_user = {}       # username -> _UserState
        self._by_addr = {}       # addr -> [timestamp, ...]

    # --- per-account lockout -------------------------------------------------

    def status(self, username, now=None):
        """Current lock state for `username`, WITHOUT recording an attempt.
        The caller checks this BEFORE verifying a password, so a locked
        account's PBKDF2 is never run."""
        now = time.time() if now is None else now
        with self._lock:
            st = self._by_user.get(username)
            if st is None or st.locked_until <= now:
                return LockStatus(locked=False)
            return LockStatus(locked=True, retry_after=st.locked_until - now,
                              lock_level=max(st.lock_level - 1, 0))

    def record_failure(self, username, addr=None, now=None):
        """Record one failed login for `username` (only called for an
        account that `status()` just confirmed is NOT currently locked).
        Returns the resulting LockStatus; `newly_locked` is True exactly on
        the call that pushed the account over the threshold."""
        now = time.time() if now is None else now
        with self._lock:
            st = self._by_user.setdefault(username, _UserState())
            st.failures = [(t, a) for t, a in st.failures if now - t <= self.window]
            st.failures.append((now, addr))
            if len(st.failures) < self.threshold:
                return LockStatus(locked=False)
            tier = min(st.lock_level, len(self.backoff_schedule) - 1)
            duration = self.backoff_schedule[tier]
            st.locked_until = now + duration
            st.lock_level += 1
            st.failures = []  # this lockout "spends" the streak that triggered it
            return LockStatus(locked=True, retry_after=duration, newly_locked=True,
                              lock_level=tier)

    def record_success(self, username):
        """A successful login resets this username's failures and lock
        level entirely (but does not touch other usernames or addresses)."""
        with self._lock:
            self._by_user.pop(username, None)

    def locked_accounts(self, now=None):
        """[{"username", "locked_until", "remaining", "lock_level"}, ...]
        for every currently-locked account -- used by the security
        dashboard. Read-only; does not mutate state."""
        now = time.time() if now is None else now
        with self._lock:
            return [
                {"username": u, "locked_until": st.locked_until,
                 "remaining": max(0.0, st.locked_until - now), "lock_level": st.lock_level}
                for u, st in self._by_user.items() if st.locked_until > now
            ]

    # --- per-source-address rate limit ---------------------------------------

    def check_address_rate(self, addr, now=None):
        """True if `addr` may make another register/login attempt right
        now; False if it has exceeded `addr_limit` attempts within
        `addr_window` seconds. Every call that returns True also counts as
        one of those attempts (call this once per incoming register/login
        envelope, regardless of whether it later succeeds)."""
        now = time.time() if now is None else now
        with self._lock:
            times = self._by_addr.setdefault(addr, [])
            times[:] = [t for t in times if now - t <= self.addr_window]
            if len(times) >= self.addr_limit:
                return False
            times.append(now)
            return True
