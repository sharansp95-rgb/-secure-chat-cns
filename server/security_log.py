"""Append-only structured security event log.

Events are JSON lines in logs/security_events.jsonl (gitignored -- see
.gitignore): one compact JSON object per line, each carrying at least `ts`
(Unix seconds) and `event` (a short event-type string). This file is
intentionally minimal -- Stage C (the Attack Lab) is the first caller, using
only "lab_control_rejected" and "lab_attack_performed"; Stage D (login
lockout + the security dashboard) adds the rest of the event types and the
reader that tails this file.

Never logs a password, a private key, a session key, or message plaintext --
every call site here passes only metadata (usernames, addresses, counts,
reasons). gui/security_dashboard.py reads this file read-only and never
connects to the server.
"""

import json
import os
import threading
import time

DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "security_events.jsonl")

# One process-wide lock: multiple client-handler threads can log concurrently,
# and a plain append is not atomic across threads without it.
_lock = threading.Lock()


def log_event(event: str, path: str = DEFAULT_LOG_PATH, **fields) -> dict:
    """Append one event and return the record that was written (useful for
    tests). `fields` are arbitrary metadata -- callers must not pass
    passwords, keys, or plaintext message content."""
    record = {"ts": time.time(), "event": event}
    record.update(fields)
    line = json.dumps(record, sort_keys=True, default=str)
    with _lock:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return record


def read_events(path: str = DEFAULT_LOG_PATH):
    """Read every event currently in the log, skipping any trailing partial
    line (e.g. a writer caught mid-append). Used by tests and the dashboard's
    initial load; the dashboard otherwise tails new lines as they appear."""
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
