"""Signed evidence export (Stage B).

Builds a self-contained JSON file from a SecureChatClient's verified
transcript so a third party (auditor, compliance officer, court) can check
WHO SAID WHAT without trusting either user or the relay server -- using
tools/verify_transcript.py, which shares no code with the client or server.

File structure (format "securechat-evidence/v1"; flat, one JSON object):

    format            "securechat-evidence/v1"
    exported_by       username of the participant who wrote this file
    exported_at       Unix seconds
    session           started_at, ended_at (Unix seconds); initiator and
                      responder usernames; ecdh_public_keys and
                      handshake_signatures ({initiator, responder}, base64) --
                      the PUBLIC, RSA-signed handshake values the hash-chain
                      genesis is derived from (see crypto_engine/hash_chain.py)
    participants      {username: {public_key_pem, fingerprint}} for both
    records           ordered list of VERIFIED messages (both directions):
                      {seq, sender, recipient, timestamp, message, prev_hash,
                       record_hash, signature(base64, by the sender)}
    chain_heads       {username: record_hash of that sender's last record, or
                      their genesis if they sent nothing}
    rejected_events   [{at, kind, sender, reason, detail}] -- anything that
                      failed a check; NEVER mixed into `records`
    exporter_signature  base64 RSA-PSS signature, by `exported_by`'s identity
                      key, over canonical_json(every other top-level field)
"""

import json
import os
import time

from crypto_engine.hash_chain import canonical_json
from crypto_engine.signatures import fingerprint, serialize_public_key, sign

FORMAT = "securechat-evidence/v1"
DEFAULT_EXPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")


class EvidenceError(Exception):
    """The client is not in a state that can produce evidence."""


def build_evidence(client, now=None):
    """Return the signed evidence dict for `client`'s current session."""
    from client.client import b64  # local import: avoids a circular import

    with client._lock:
        record = client.handshake_record
        transcript = list(client.transcript)
        rejected = list(client.rejected_events)
        started = client.session_started_at
        out_head = client._out_chain.head if client._out_chain else None
        in_head = client._in_chain.head if client._in_chain else None
    if record is None or client.rsa_private_key is None or client.peer_public_key_pem is None:
        raise EvidenceError(
            "No established, signed session yet -- complete the handshake "
            "before exporting evidence.")

    now = int(now if now is not None else time.time())
    own_pem = serialize_public_key(client.rsa_private_key.public_key()).decode("ascii")
    peer_pem = client.peer_public_key_pem
    if isinstance(peer_pem, bytes):
        peer_pem = peer_pem.decode("ascii")

    body = {
        "format": FORMAT,
        "exported_by": client.username,
        "exported_at": now,
        "session": {
            "started_at": started,
            "ended_at": now,
            "initiator": record["initiator"],
            "responder": record["responder"],
            "ecdh_public_keys": {
                "initiator": b64(record["initiator_pub"]),
                "responder": b64(record["responder_pub"]),
            },
            "handshake_signatures": {
                "initiator": b64(record["initiator_sig"]),
                "responder": b64(record["responder_sig"]),
            },
        },
        "participants": {
            client.username: {"public_key_pem": own_pem,
                              "fingerprint": fingerprint(own_pem)},
            client.peer: {"public_key_pem": peer_pem,
                          "fingerprint": fingerprint(peer_pem)},
        },
        "records": transcript,
        "chain_heads": {client.username: out_head, client.peer: in_head},
        "rejected_events": rejected,
    }
    body["exporter_signature"] = b64(sign(client.rsa_private_key, canonical_json(
        {k: v for k, v in body.items() if k != "exporter_signature"})))
    return body


def export_evidence(client, directory=DEFAULT_EXPORT_DIR, now=None):
    """Write the evidence file into `directory` (created if needed) and
    return its path."""
    evidence = build_evidence(client, now=now)
    os.makedirs(directory, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(evidence["exported_at"]))
    path = os.path.join(directory,
                        f"evidence_{client.username}_{client.peer}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path
