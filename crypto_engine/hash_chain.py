"""Hash-chained conversation log (Stage A: tamper-evident conversations).

Problem this solves
-------------------
Per-message AES-GCM + RSA signatures prove each message is *authentic*, but
they say nothing about the conversation as a whole: a malicious relay can
silently DROP a valid message, or REORDER two of them, and neither client
would notice -- every message that does arrive still verifies.

Design
------
Every sender keeps its own chain. Each outgoing message carries:

  seq        per-sender counter, starting at 1
  prev_hash  hex SHA-256 of that sender's previous canonical record, or, for
             the first message, a fixed per-session, per-sender GENESIS value

Both fields live inside the RSA-signed, AES-GCM-encrypted payload, so the
relay can neither read nor alter them, and the signature covers them.

Canonical record (what is signed AND hashed -- the Stage B offline verifier
reproduces this byte-for-byte)
-------------------------------
    canonical_json({
        "sender": str, "recipient": str, "seq": int, "timestamp": int,
        "message": str, "prev_hash": str (64 lowercase hex chars)
    })

where canonical_json(obj) = json.dumps(obj, sort_keys=True,
separators=(",", ":"), ensure_ascii=True).encode("ascii").
  * record_hash  = SHA-256(canonical record bytes), lowercase hex
  * signature    = RSA-PSS/SHA-256 over the canonical record bytes

Genesis (so two different sessions never share a chain start)
-------------------------------------------------------------
    genesis(sender) = SHA-256( b"securechat/genesis/v1\\x00"
                               + initiator_ecdh_pubkey (32 raw bytes)
                               + responder_ecdh_pubkey (32 raw bytes)
                               + sender.encode("utf-8") )
The two ECDH public keys are PUBLIC handshake values (both are RSA-signed
during the handshake), so an offline verifier can recompute genesis from the
evidence file without ever seeing a secret. Including the sender name gives
each direction its own distinct chain start.

Receive-side verdicts (IncomingChain.check)
-------------------------------------------
  OK      seq is exactly the expected next value and prev_hash matches
  GAP     seq is ahead of expected: message(s) missing -> possible deletion
          by the relay. The message itself is authentic, so the chain
          RESYNCS to it (later messages are judged against it), but the
          gap is reported.
  BROKEN  seq is behind expected (replay/reorder/duplicate), or seq is right
          but prev_hash does not match (injection/reorder). The message is
          not accepted and the chain does not advance.
"""

import hashlib
import json

__all__ = [
    "GENESIS_PREFIX",
    "canonical_json",
    "canonical_record",
    "record_hash",
    "genesis_hash",
    "OutgoingChain",
    "IncomingChain",
    "ChainVerdict",
    "OK",
    "GAP",
    "BROKEN",
]

GENESIS_PREFIX = b"securechat/genesis/v1\x00"

OK = "ok"
GAP = "gap"
BROKEN = "broken"


def canonical_json(obj) -> bytes:
    """The one canonical JSON encoding used for signed/hashed data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def canonical_record(sender, recipient, seq, timestamp, message, prev_hash) -> bytes:
    """Canonical bytes of one chat record -- what is signed and hashed."""
    return canonical_json({
        "sender": sender,
        "recipient": recipient,
        "seq": seq,
        "timestamp": timestamp,
        "message": message,
        "prev_hash": prev_hash,
    })


def record_hash(record_bytes: bytes) -> str:
    return hashlib.sha256(record_bytes).hexdigest()


def genesis_hash(initiator_pub: bytes, responder_pub: bytes, sender: str) -> str:
    """Session-specific, sender-specific chain start (see module docstring)."""
    return hashlib.sha256(
        GENESIS_PREFIX + bytes(initiator_pub) + bytes(responder_pub) + sender.encode("utf-8")
    ).hexdigest()


class OutgoingChain:
    """Our own sending direction: hands out the next (seq, prev_hash) and
    advances once the record has been built."""

    def __init__(self, sender, genesis):
        self.sender = sender
        self.next_seq = 1
        self.head = genesis  # hash of our last record, or genesis

    def next_fields(self):
        return self.next_seq, self.head

    def commit(self, record_bytes: bytes) -> str:
        """Record that `record_bytes` was sent; returns its hash."""
        self.head = record_hash(record_bytes)
        self.next_seq += 1
        return self.head


class ChainVerdict:
    def __init__(self, status, expected_seq, got_seq, detail="", missing=0, explained=0):
        self.status = status
        self.expected_seq = expected_seq
        self.got_seq = got_seq
        self.detail = detail
        self.missing = missing        # GAP: how many sequence numbers were skipped
        self.explained = explained    # GAP: how many of them match messages rejected earlier

    @property
    def ok(self):
        return self.status == OK

    def __repr__(self):
        return f"ChainVerdict({self.status}, expected={self.expected_seq}, got={self.got_seq})"


class IncomingChain:
    """The peer's sending direction, as seen by the receiver."""

    def __init__(self, sender, genesis):
        self.sender = sender
        self.expected_seq = 1
        self.head = genesis  # hash of the last record we accepted, or genesis
        # Nonces of messages from this sender that were REJECTED (failed AES-GCM, signature,
        # freshness...) since the last accepted one. Such a message was really sent, so the
        # sender's seq advanced, but it never reached the chain: the next valid message then
        # skips its number. Counting them lets that gap be reported accurately ("1 missing, it
        # matches the message rejected earlier") instead of as an unexplained deletion. A set
        # of nonces, so the same bad message delivered twice (e.g. replayed) counts once.
        self._rejected_nonces = set()

    def note_rejected(self, nonce):
        """Record that a message from this sender was rejected before the chain saw it."""
        self._rejected_nonces.add(nonce)

    def check(self, recipient, seq, timestamp, message, prev_hash):
        """Judge one already-decrypted, already-signature-verified record.
        Advances the chain on OK and GAP; leaves it untouched on BROKEN."""
        record = canonical_record(self.sender, recipient, seq, timestamp, message, prev_hash)
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return ChainVerdict(BROKEN, self.expected_seq, seq, "invalid sequence number")

        if seq < self.expected_seq:
            return ChainVerdict(
                BROKEN, self.expected_seq, seq,
                f"sequence went backwards (got #{seq}, expected #{self.expected_seq}): "
                f"chain broken, possible reordering, replay or injection")

        if seq == self.expected_seq:
            if prev_hash != self.head:
                return ChainVerdict(
                    BROKEN, self.expected_seq, seq,
                    f"prev_hash does not match message #{seq - 1}: chain broken, "
                    f"possible reordering or injection")
            self.head = record_hash(record)
            self.expected_seq = seq + 1
            self._rejected_nonces.clear()
            return ChainVerdict(OK, seq, seq)

        # seq > expected: messages are missing. The message is authentic
        # (signature already verified), so resync to it but report the gap.
        missing = seq - self.expected_seq
        explained = min(missing, len(self._rejected_nonces))
        # STRICT: a gap is always reported (status GAP), explained or not. "Explained" only
        # means the count matches messages this client itself rejected and showed a card for;
        # the wording says so without claiming the gap is harmless.
        if explained == 0:
            detail = (f"{missing} message(s) missing before #{seq} (expected "
                      f"#{self.expected_seq}): possible deletion by the relay")
        elif explained == missing:
            detail = (f"{missing} message(s) missing before #{seq} (expected "
                      f"#{self.expected_seq}): matches {explained} message(s) rejected earlier, "
                      f"which were never shown")
        else:
            detail = (f"{missing} message(s) missing before #{seq} (expected "
                      f"#{self.expected_seq}): {explained} match message(s) rejected earlier, "
                      f"{missing - explained} unaccounted for: possible deletion by the relay")
        verdict = ChainVerdict(GAP, self.expected_seq, seq, detail, missing, explained)
        self.head = record_hash(record)
        self.expected_seq = seq + 1
        self._rejected_nonces.clear()      # resynchronised: the next message starts clean
        return verdict
