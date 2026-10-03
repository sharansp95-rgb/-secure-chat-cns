"""Plain-English wording for what the security checks report -- no Tk, no network.

Presentation only. Every function here takes the data of an event that a REAL check
already produced (the SecureChatClient's `message_rejected` / `chain_warning` /
`handshake_aborted` events, or a line of the server's security log) and turns it into
words for the audience. Nothing here decides whether something is secure or insecure.
"""

# reason code (client event `reason`) -> what to tell the audience.
#   title    short headline
#   explain  one plain-English sentence on what happened
#   check    the actual defence that fired (shown as "Caught by")
REJECTIONS = {
    "decryption_failed": {
        "title": "tampered in transit",
        "explain": "The relay changed this message on its way. Its AES-GCM authentication "
                   "tag no longer matched, so nothing was shown.",
        "check": "AES-256-GCM authentication tag",
    },
    "replay_duplicate": {
        "title": "replayed message",
        "explain": "This exact message had already been received. The duplicate was "
                   "discarded, so an old message can't be sent again.",
        "check": "Duplicate nonce / timestamp check",
    },
    "stale_timestamp": {
        "title": "message too old",
        "explain": "The message's timestamp is outside the freshness window, so it may be "
                   "an old message replayed later.",
        "check": "Timestamp freshness window",
    },
    "signature_failed": {
        "title": "sender signature invalid",
        "explain": "The RSA signature does not match the sender's key, so this message may "
                   "be forged or altered.",
        "check": "RSA signature (PSS / SHA-256)",
    },
    "chain_broken": {
        "title": "history does not match",
        "explain": "This message does not link to the previous one in the hash chain, so "
                   "earlier messages were altered, reordered or replaced.",
        "check": "Hash chain (prev_hash link)",
    },
    "chain_gap": {
        "title": "message missing",
        "explain": "One or more messages are missing from the sequence. The message that "
                   "did arrive is shown, but flagged.",
        "check": "Hash-chain sequence number",
    },
    "unknown_peer_key": {
        "title": "unknown sender key",
        "explain": "There is no verified public key for this sender yet, so the signature "
                   "cannot be checked.",
        "check": "Peer public-key lookup",
    },
    "malformed": {
        "title": "malformed message",
        "explain": "The message was not in the expected format and was discarded.",
        "check": "Envelope format check",
    },
    "no_session_key": {
        "title": "no secure session yet",
        "explain": "A message arrived before the key exchange finished, so it could not be "
                   "decrypted.",
        "check": "Session state",
    },
}

HANDSHAKE_SIGNATURE = {
    "title": "signature check failed",
    "explain": "The key offered during the handshake was not signed by your peer's RSA "
               "identity key, so it may have been swapped. No session was created.",
    "check": "RSA signature on the ECDH handshake",
}
HANDSHAKE_OTHER = {
    "title": "could not complete",
    "explain": "The handshake was aborted, so no session key was created.",
    "check": "Handshake verification",
}


def describe_rejection(kind, reason, detail=None):
    """Describe a `message_rejected` / `chain_warning` / `handshake_aborted` event.

    Returns {"title", "explain", "check", "detail", "severity"}: severity is "bad" for
    something that was blocked, "warn" for something that was flagged but still shown
    (a gap in the hash chain)."""
    if kind == "handshake_aborted":
        base = HANDSHAKE_SIGNATURE if "did not verify" in (reason or "").lower() else HANDSHAKE_OTHER
        severity, prefix = "bad", "Handshake blocked"
    else:
        base = REJECTIONS.get(reason) or {
            "title": "rejected", "explain": "A security check rejected this message.",
            "check": "Client-side verification"}
        severity, prefix = ("warn", "Warning") if kind == "chain_warning" else ("bad", "Message blocked")
    return {**base, "headline": f"{prefix}: {base['title']}", "severity": severity,
            "detail": detail if detail else (reason if kind == "handshake_aborted" else None)}


# --- "What just happened?" banners ------------------------------------------------------
#
# One or two plain sentences shown under the header when something important happens.
# Triggered ONLY by events a real check or the real session produced; the wording describes
# what that check does, it never decides the outcome.

BANNER_TEXT = {
    "session_established": (
        "ok", "Keys were exchanged with ECDH and the exchange was signed with RSA. "
              "The server never saw the key."),
    "decryption_failed": (
        "bad", "The relay changed one byte. AES-GCM's authentication tag no longer matched, "
               "so the message was rejected."),
    "replay_duplicate": (
        "bad", "An old message was sent again. The duplicate nonce/timestamp check "
               "rejected it."),
    "stale_timestamp": (
        "bad", "An old message arrived late. The timestamp freshness check rejected it."),
    "signature_failed": (
        "bad", "The sender's RSA signature did not verify, so the message was rejected as "
               "possibly forged."),
    "chain_broken": (
        "bad", "The message does not link to the conversation so far. The hash chain "
               "rejected it."),
    "chain_gap": (
        "warn", "A message is missing. The hash chain noticed the gap in the sequence."),
    "handshake_signature": (
        "bad", "Someone swapped the key during the handshake. The RSA signature check "
               "failed, so no session was created."),
    "handshake_other": (
        "bad", "The key exchange could not complete, so no session was created."),
    "evidence_exported": (
        "ok", "A signed copy of this conversation was saved. Anyone can verify it offline."),
}


def banner_for(kind, data=None):
    """The (severity, text) banner for an event, or None if the event is not newsworthy.

    `kind`/`data` are a SecureChatClient event (handshake_established, message_rejected,
    chain_warning, handshake_aborted, lab_attack_performed) or the window's own
    "evidence_exported". Severity is one of "ok", "bad", "warn", "info"."""
    data = data or {}
    if kind == "handshake_established":
        return BANNER_TEXT["session_established"]
    if kind == "message_rejected":
        reason = data.get("reason")
        if reason in BANNER_TEXT:
            return BANNER_TEXT[reason]
        info = REJECTIONS.get(reason)
        return ("bad", info["explain"]) if info else None
    if kind == "chain_warning":
        return BANNER_TEXT["chain_gap"]
    if kind == "handshake_aborted":
        verified = "did not verify" in (data.get("reason") or "").lower()
        return BANNER_TEXT["handshake_signature" if verified else "handshake_other"]
    if kind == "evidence_exported":
        return BANNER_TEXT["evidence_exported"]
    if kind == "lab_attack_performed":
        peer = data.get("peer") or "your peer"
        return ("info", f"The relay just carried out the attack ({data.get('detail')}). "
                        f"Watch {peer}'s window: their own checks decide whether it is caught.")
    return None


# --- Attack Lab cards -----------------------------------------------------------------
#
# What each one-shot relay attack is, which defence is EXPECTED to catch it, and which
# report from the victim's client proves it was. The attacker's own client is never told
# whether the victim caught the attack; the victim's client reports its real detection to
# the server (a `security_alert`), which logs it. `find_lab_detection` looks for exactly
# that record -- it never decides anything itself.

LAB_ATTACKS = [
    {"action": "tamper_next", "label": "Tamper next message", "title": "Tamper", "glyph": "✂",
     "desc": "The relay flips one byte of your next message in transit.",
     "check": REJECTIONS["decryption_failed"]["check"],
     "alert": "message_rejected", "reason": "decryption_failed",
     "armed": "Armed: send a message now"},
    {"action": "replay_last", "label": "Replay last message", "title": "Replay", "glyph": "↻",
     "desc": "The relay immediately resends your most recent message a second time.",
     "check": REJECTIONS["replay_duplicate"]["check"],
     "alert": "message_rejected", "reason": "replay_duplicate",
     "armed": "Armed: replaying now"},
    {"action": "drop_next", "label": "Drop next message", "title": "Drop", "glyph": "⊘",
     "desc": "The relay silently discards your next message; it never reaches your peer.",
     "check": REJECTIONS["chain_gap"]["check"],
     "alert": "chain_warning", "reason": "chain_gap",
     "armed": "Armed: send two messages (the gap shows on the second)"},
    {"action": "mitm_next_handshake", "label": "MITM next handshake", "title": "Man in the middle",
     "glyph": "⇄",
     "desc": "The relay swaps in its own key during the next handshake you start.",
     "check": HANDSHAKE_SIGNATURE["check"],
     "alert": "handshake_aborted", "reason": None,
     "armed": "Armed: arm this before your peer logs in"},
]
LAB_BY_ACTION = {a["action"]: a for a in LAB_ATTACKS}
LAB_SILENT_AFTER_SECONDS = 10


def find_lab_detection(action, events, victim, since):
    """The victim's own report of catching `action`, from the security log, or None.

    `events` are security-log records; a match must be a `security_alert` reported by
    `victim`, logged at or after `since`, with the alert kind (and reason, where the
    attack has one) that this attack should trigger."""
    attack = LAB_BY_ACTION[action]
    for event in events:
        if (event.get("event") == "security_alert" and event.get("reported_by") == victim
                and float(event.get("ts", 0)) >= since and event.get("alert") == attack["alert"]
                and (attack["reason"] is None or event.get("reason") == attack["reason"])):
            return event
    return None


def lab_status(state, action, peer, detail=None):
    """(chip kind, text) for an Attack Lab card. `state` is idle, arming, armed, fired,
    caught, silent or rejected."""
    attack = LAB_BY_ACTION[action]
    return {
        "idle": ("off", "Not armed"),
        "arming": ("warn", "Arming..."),
        "armed": ("warn", attack["armed"]),
        "fired": ("warn", f"Fired. Waiting for {peer}'s check..."),
        "caught": ("ok", f"Caught by {attack['check']} (reported by {peer})"),
        "silent": ("warn", f"No report from {peer} yet. Watch {peer}'s window."),
        "rejected": ("bad", f"Rejected: {detail}"),
    }[state]


# --- Security receipt -------------------------------------------------------------------
#
# A receipt exists only for a message that already passed EVERY client-side check (the
# client attaches it to message_sent / message_received). These functions only word what
# those checks verified; they never re-check anything.


def receipt_rows(receipt):
    """[(kind, title, detail)] -- one row per check. kind is "ok" or "warn"."""
    if receipt.get("direction") == "sent":
        return [
            ("ok", "Signed by you", "RSA-PSS / SHA-256 with your private key"),
            ("ok", "Encrypted", "AES-256-GCM with a fresh nonce for every message"),
            ("ok", "Chained", f"Message #{receipt.get('seq')} in your direction, linked to your "
                              f"previous message"),
        ]
    sender = receipt.get("sender") or "the sender"
    rows = [
        ("ok", "Not tampered with", "AES-256-GCM authentication tag verified"),
        ("ok", f"Really from {sender}", "RSA signature verified against their public key"),
        ("ok", "Fresh", f"Arrived {receipt.get('age_seconds', 0)} s after it was sent, inside "
                        f"the freshness window"),
    ]
    if receipt.get("chain_link") == "gap":
        rows.append(("warn", "Earlier message missing",
                     f"Message #{receipt.get('seq')} arrived, but earlier messages are missing "
                     f"before it"))
    else:
        rows.append(("ok", "In order", f"Message #{receipt.get('seq')} links to the one before it"))
    return rows


def receipt_summary(receipt):
    """(kind, one plain-English sentence) for the bottom of the receipt."""
    if receipt.get("direction") == "sent":
        return ("ok", "This message was signed with your key, encrypted, and chained to your "
                      "previous message. Your peer's client verifies it when it arrives.")
    if receipt.get("chain_link") == "gap":
        return ("warn", "This message is authentic and unmodified, but earlier messages are "
                        "missing before it.")
    return ("ok", "This message is authentic, unmodified, fresh, and in order.")


def receipt_details(receipt):
    """[(label, full value, is_mono)] for the technical values; each gets a Copy button."""
    import time as _time
    sent = receipt.get("direction") == "sent"
    details = [("Sender", f"{receipt.get('sender')}  ({receipt.get('sender_fingerprint') or 'no fingerprint'})",
                False)]
    if receipt.get("timestamp") is not None:
        stamp = _time.strftime("%H:%M:%S", _time.localtime(float(receipt["timestamp"])))
        details.append(("Sent at" if sent else "Sent by peer at", stamp, False))
    details += [
        ("Nonce", receipt.get("nonce") or "-", True),
        ("prev_hash", receipt.get("prev_hash") or "-", True),
        ("Record SHA-256", receipt.get("record_hash") or "-", True),
    ]
    return details


def shorten(value, n=22):
    value = value or "-"
    return value if len(value) <= n else value[:n] + "…"


# --- Security dashboard -------------------------------------------------------------------
#
# The dashboard only READS logs/security_events.jsonl. These pure functions turn those
# records into readable one-liners, KPI numbers and the list of currently locked accounts.

ACTION_NAMES = {
    "tamper_next": "tampering with a message",
    "replay_last": "replaying a message",
    "drop_next": "dropping a message",
    "mitm_next_handshake": "a man-in-the-middle key swap",
}
_ALERT_WORDS = {
    "chain_warning": "flagged a gap in the hash chain",
    "handshake_aborted": "refused a tampered key exchange (RSA signature)",
}


def _seconds(value):
    try:
        return f"{float(value):.0f} s"
    except (TypeError, ValueError):
        return "a while"


def describe_log_event(event):
    """(glyph, severity, one-line text) for a security-log record. severity is one of
    "info", "ok", "warn", "bad". Unknown event types still get a sensible line."""
    kind = event.get("event", "?")
    user = event.get("username")
    addr = event.get("from_addr")
    if kind == "user_registered":
        return "✚", "info", f"{user} registered a new account"
    if kind == "user_login":
        return "➜", "ok", f"{user} logged in"
    if kind == "failed_login":
        return "✕", "warn", f"Failed login for {user} (from {addr})"
    if kind == "account_locked":
        return "■", "bad", (f"{user} locked out for {_seconds(event.get('retry_after'))} after "
                            f"repeated failed logins (lockout #{int(event.get('lock_level', 0)) + 1})")
    if kind == "lockout_rejected":
        return "⊘", "warn", (f"Login attempt on locked account {user} refused "
                             f"({_seconds(event.get('retry_after'))} left)")
    if kind == "address_rate_limited":
        return "⚑", "warn", (f"{addr} slowed down: too many connection attempts "
                             f"({event.get('attempted_type')})")
    if kind == "non_tls_connection":
        return "!", "warn", f"Connection from {addr} refused: not a TLS client"
    if kind == "malformed_envelope":
        return "!", "warn", f"Malformed message from {event.get('from_user') or addr} ignored"
    if kind == "lab_control_rejected":
        return "⚠", "warn", (f"Attack Lab request from {event.get('requested_by')} refused "
                             f"({event.get('reason')})")
    if kind == "lab_attack_performed":
        what = ACTION_NAMES.get(event.get("action"), event.get("action"))
        return "✂", "warn", (f"Relay attack performed: {what} on {event.get('target')}'s traffic "
                             f"(armed by {event.get('armed_by')})")
    if kind == "security_alert":
        who, peer = event.get("reported_by"), event.get("peer")
        alert, reason = event.get("alert"), event.get("reason")
        if alert == "message_rejected" and reason in REJECTIONS:
            r = REJECTIONS[reason]
            return "◆", "bad", (f"{who}'s client blocked a message from {peer}: {r['title']} "
                                f"(caught by {r['check']})")
        return "◆", "bad", f"{who}'s client {_ALERT_WORDS.get(alert, 'reported: ' + str(alert))}" \
                           f" (peer {peer})"
    details = ", ".join(f"{k}={v}" for k, v in event.items() if k not in ("ts", "event"))
    return "•", "info", f"{kind}: {details}" if details else kind


def compute_kpis(events):
    """The dashboard's top tiles, from the log records only."""
    users = {e.get("username") for e in events
             if e.get("event") in ("user_login", "user_registered") and e.get("username")}
    return {
        "attacks_detected": sum(1 for e in events if e.get("event") == "security_alert"),
        "failed_logins": sum(1 for e in events if e.get("event") == "failed_login"),
        "active_users": len(users),
    }


def lock_records(events):
    """{username: {"locked_until", "lock_level"}} by replaying the log: a lock lasts until its
    recorded retry_after; a later successful login (user_login) clears it early."""
    locks = {}
    for event in events:
        if event.get("event") == "account_locked":
            locks[event.get("username")] = {
                "locked_until": float(event.get("ts", 0)) + float(event.get("retry_after", 0)),
                "lock_level": event.get("lock_level", 0)}
        elif event.get("event") == "user_login":
            locks.pop(event.get("username"), None)
    return locks


def locked_accounts(events, now):
    """Accounts still locked at `now`: {username: {"locked_until", "lock_level", "remaining"}}."""
    return {u: {**d, "remaining": max(0.0, d["locked_until"] - now)}
            for u, d in lock_records(events).items() if d["locked_until"] > now}


def countdown(seconds):
    """0:42 style countdown text."""
    seconds = max(0, int(seconds))
    return f"{seconds // 60}:{seconds % 60:02d}"
