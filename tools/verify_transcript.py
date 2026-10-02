#!/usr/bin/env python3
"""Independent offline verifier for Secure Chat evidence files.

    python tools/verify_transcript.py exports/<file>.json
    python tools/verify_transcript.py exports/<file>.json --expect-fingerprint "A1B2 C3D4 E5F6 A7B8"

Lets a third party (auditor, compliance officer, court) check WHO SAID WHAT
without trusting either user or the relay server. It deliberately imports NO
client or server code -- only crypto_engine (RSA verification, the canonical
record encoding and the hash helpers) and the standard library -- so a bug or
backdoor in the chat application cannot make bad evidence look good.

What it checks
--------------
  1. every participant's claimed fingerprint matches their embedded public key
  2. (optional) --expect-fingerprint pins a fingerprint you obtained out of
     band; without a pin, the file only proves consistency with ITS OWN keys
  3. both RSA-signed ECDH handshake values verify, and the per-sender chain
     genesis is recomputed from them
  4. for every record: the sender's RSA signature over the canonical record,
     that record_hash really is SHA-256 of the canonical record, and that
     seq / prev_hash continue that sender's chain from genesis (a gap, a
     reorder or an edited predecessor all show up here)
  5. the claimed chain heads equal the recomputed ones (catches a deleted
     LAST message)
  6. the exporter's signature over the whole file (catches any edit after
     export, including metadata)

Exit status: 0 = VALID, 1 = INVALID, 2 = unreadable file / bad usage.
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_engine.hash_chain import (  # noqa: E402
    canonical_json,
    canonical_record,
    genesis_hash,
    record_hash,
)
from crypto_engine.signatures import deserialize_public_key, fingerprint, verify  # noqa: E402

FORMAT = "securechat-evidence/v1"
OK_MARK, BAD_MARK = "✔", "✘"


class Report:
    def __init__(self):
        self.lines = []
        self.failures = []  # (record index or None, check name, detail)

    def ok(self, text):
        self.lines.append(f"  {OK_MARK} {text}")

    def bad(self, text, index=None, check=""):
        self.lines.append(f"  {BAD_MARK} {text}")
        self.failures.append((index, check, text))

    def heading(self, text):
        self.lines.append(f"\n{text}")

    @property
    def valid(self):
        return not self.failures

    def render(self):
        out = list(self.lines)
        out.append("")
        if self.valid:
            out.append(f"RESULT: VALID {OK_MARK}  every signature, chain link and the "
                       f"export signature checked out.")
        else:
            first = self.failures[0]
            where = f"record #{first[0]}" if first[0] is not None else "the file as a whole"
            out.append(f"RESULT: INVALID {BAD_MARK}  {len(self.failures)} check(s) failed; "
                       f"first failure: {where} -- {first[1]}.")
        return "\n".join(out)


def _unb64(text):
    return base64.b64decode(text.encode("ascii"), validate=True)


def verify_evidence(data, expect_fingerprints=()):
    """Verify an already-parsed evidence dict. Returns a Report."""
    r = Report()
    r.heading("Structure")
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        r.bad(f"not a {FORMAT} file", check="format")
        return r
    try:
        session = data["session"]
        participants = data["participants"]
        records = data["records"]
        chain_heads = data["chain_heads"]
        exporter = data["exported_by"]
        exporter_sig = data["exporter_signature"]
        names = list(participants)
        assert len(names) == 2 and all(n in participants for n in
                                       (session["initiator"], session["responder"]))
    except (KeyError, TypeError, AssertionError):
        r.bad("missing or malformed fields (session/participants/records/...)",
              check="structure")
        return r
    r.ok(f"format {FORMAT}; participants {names[0]} and {names[1]}; "
         f"{len(records)} record(s); exported by {exporter}")

    # --- keys and fingerprints ---------------------------------------------
    r.heading("Participant keys")
    keys = {}
    for name, info in participants.items():
        try:
            keys[name] = deserialize_public_key(info["public_key_pem"].encode("ascii"))
        except (ValueError, KeyError, TypeError, AttributeError):
            r.bad(f"{name}: public key could not be parsed", check="public key")
            continue
        actual = fingerprint(info["public_key_pem"])
        if actual == info.get("fingerprint"):
            r.ok(f"{name}: fingerprint {actual} matches the embedded public key")
        else:
            r.bad(f"{name}: claimed fingerprint {info.get('fingerprint')} does NOT match "
                  f"the embedded key ({actual})", check="fingerprint")
    for pin in expect_fingerprints:
        want = pin.strip().upper()
        if any(fingerprint(p["public_key_pem"]) == want for p in participants.values()):
            r.ok(f"pinned fingerprint {want} belongs to a participant")
        else:
            r.bad(f"pinned fingerprint {want} matches NO participant's key -- these may "
                  f"not be the identities you expected", check="pinned fingerprint")
    if not expect_fingerprints:
        r.lines.append("  (no --expect-fingerprint given: keys are only checked for "
                       "consistency with this file itself)")

    # --- handshake and genesis ---------------------------------------------
    r.heading("Handshake")
    genesis = {}
    try:
        init_pub = _unb64(session["ecdh_public_keys"]["initiator"])
        resp_pub = _unb64(session["ecdh_public_keys"]["responder"])
        init_sig = _unb64(session["handshake_signatures"]["initiator"])
        resp_sig = _unb64(session["handshake_signatures"]["responder"])
        handshake_ok = True
    except (KeyError, ValueError, TypeError):
        r.bad("handshake values missing or not valid base64", check="handshake")
        handshake_ok = False
    if handshake_ok:
        for role, pub, sig in (("initiator", init_pub, init_sig),
                               ("responder", resp_pub, resp_sig)):
            who = session[role]
            if who in keys and verify(keys[who], pub, sig):
                r.ok(f"{role} {who}: ECDH public key carries a valid RSA signature")
            else:
                r.bad(f"{role} {who}: ECDH public key signature is INVALID",
                      check="handshake signature")
        for name in names:
            genesis[name] = genesis_hash(init_pub, resp_pub, name)

    # --- records ------------------------------------------------------------
    r.heading("Messages")
    expected = {n: {"seq": 1, "head": genesis.get(n)} for n in names}
    for index, rec in enumerate(records, start=1):
        label = None
        try:
            sender, recipient = rec["sender"], rec["recipient"]
            seq, prev = rec["seq"], rec["prev_hash"]
            label = f"#{index} {sender}→{recipient} seq {seq} \"{_clip(rec['message'])}\""
            signable = canonical_record(sender, recipient, seq, rec["timestamp"],
                                        rec["message"], prev)
            problems = []
            if sender not in keys or recipient not in participants or sender == recipient:
                problems.append(("participants", "sender/recipient are not the two participants"))
            elif not verify(keys[sender], signable, _unb64(rec["signature"])):
                problems.append(("signature", "RSA signature does NOT verify (message or "
                                              "chain fields were altered, or wrong key)"))
            real_hash = record_hash(signable)
            if real_hash != rec.get("record_hash"):
                problems.append(("record hash", "record_hash does not match the record's content"))
            state = expected.get(sender)
            if state is not None and state["head"] is not None:
                if seq == state["seq"] and prev == state["head"]:
                    pass
                elif isinstance(seq, int) and seq > state["seq"]:
                    problems.append(("chain", f"GAP: {seq - state['seq']} message(s) from "
                                              f"{sender} missing before seq {seq} "
                                              f"(expected {state['seq']})"))
                elif isinstance(seq, int) and seq < state["seq"]:
                    problems.append(("chain", f"seq {seq} appears after seq "
                                              f"{state['seq'] - 1}: reordered or duplicated"))
                else:
                    problems.append(("chain", "prev_hash does not link to the previous "
                                              "record: an earlier message was edited, "
                                              "removed or replaced"))
                # Resync to this record so one defect is reported once, not
                # as a cascade over every later message.
                if isinstance(seq, int):
                    state["seq"], state["head"] = seq + 1, real_hash
        except (KeyError, TypeError, ValueError):
            r.bad(f"#{index}: malformed record", index=index, check="record format")
            continue
        if problems:
            for check_name, detail in problems:
                r.bad(f"{label}: {check_name} -- {detail}", index=index, check=check_name)
        else:
            r.ok(f"{label}: signature ✔  hash ✔  chain ✔")

    # --- chain heads --------------------------------------------------------
    r.heading("Chain heads")
    for name in names:
        state = expected[name]
        claimed = chain_heads.get(name) if isinstance(chain_heads, dict) else None
        if state["head"] is None:
            continue
        if claimed == state["head"]:
            r.ok(f"{name}: final chain head matches ({state['seq'] - 1} message(s) sent)")
        else:
            r.bad(f"{name}: claimed final chain head does not match the records "
                  f"(a trailing message was removed or altered)", check="chain head")

    # --- exporter signature -------------------------------------------------
    r.heading("Export signature")
    body = {k: v for k, v in data.items() if k != "exporter_signature"}
    try:
        if exporter in keys and verify(keys[exporter], canonical_json(body),
                                       _unb64(exporter_sig)):
            r.ok(f"whole file is signed by {exporter}; nothing was changed after export")
        else:
            r.bad(f"exporter signature by {exporter} is INVALID -- the file was edited "
                  f"after export (or was not signed by {exporter})", check="export signature")
    except (ValueError, TypeError):
        r.bad("exporter signature is not valid base64", check="export signature")
    return r


def _clip(text, n=40):
    text = str(text).replace("\n", " ")
    return text if len(text) <= n else text[:n - 1] + "…"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a Secure Chat evidence file offline.")
    parser.add_argument("file", help="path to an exports/*.json evidence file")
    parser.add_argument("--expect-fingerprint", action="append", default=[], metavar="FP",
                        help="a participant fingerprint you trust (repeatable); the file "
                             "is INVALID if no participant has it")
    args = parser.parse_args(argv)
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read evidence file: {exc}", file=sys.stderr)
        return 2
    print(f"Verifying {args.file}")
    report = verify_evidence(data, args.expect_fingerprint)
    print(report.render())
    return 0 if report.valid else 1


if __name__ == "__main__":
    sys.exit(main())
