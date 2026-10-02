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
