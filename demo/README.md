# Demo artifacts (Review 2 / final report evidence)

This folder holds the evidence artifacts for the security properties this project
claims, and the scripts used to reproduce them live. For the full click-by-click live
demo script (what to click, what should appear, what to say), see
[`full_walkthrough.md`](full_walkthrough.md).

## Live demo scripts

Each script is standalone: it starts its own real mini relay server (the actual
`server/server.py` code, real TLS) and drives two real clients (the actual
`client/client.py` code) against it — nothing here is mocked or simulated. Each prints
a clear `[PASS]`/`[FAIL]` banner per check and a final overall result. Run them from
the project root, after `python certs/generate_certs.py` has been run at least once:

```
python demo/run_tamper_demo.py
python demo/run_replay_demo.py
python demo/run_mitm_handshake_demo.py
python demo/run_drop_demo.py
python demo/run_evidence_demo.py
```

| Script | What it proves |
|---|---|
| `run_tamper_demo.py` | A malicious/compromised relay that flips a single ciphertext byte in transit cannot get a tampered message displayed — AES-GCM's authentication tag (Phase 2/3) catches it, and the client shows a clear rejection instead of garbage. |
| `run_replay_demo.py` | A relay that captures a valid chat message and resends it a second time cannot get it displayed twice — the Phase 7b timestamp + duplicate-nonce tracking rejects the replay, even though the resent envelope is byte-for-byte identical to (and therefore passes every check that) the original valid message. |
| `run_mitm_handshake_demo.py` | A malicious relay that tries the classic unauthenticated-Diffie-Hellman attack — substituting its own ECDH public key for a peer's during the handshake — is stopped by the Phase 7a signed handshake: the victim's client derives no session key at all, and also shows that the resulting RSA key fingerprint (the human-verifiable backstop) would not have matched anyway. |
| `run_drop_demo.py` | A relay silently dropping one valid message is detected by the hash-chained conversation log: the receiver sees message #3 where #2 was expected and warns "possible deletion by the relay". The authentic message is still delivered, flagged. |
| `run_evidence_demo.py` | A real conversation is exported as signed evidence and verified VALID by `tools/verify_transcript.py` (which imports no client/server code); a copy with one word changed is INVALID, with the exact message and failed check named. |

## Wireshark capture

`capture_normal_session.pcapng` (committed in this folder) is a real capture of a
normal session — registration, login, handshake, and a few chat messages — recorded from
the very first packet (two TLS 1.3 handshakes, so the handshake is visible), following
[`capture_instructions.md`](capture_instructions.md), which also documents the exact
filter and steps to produce your own capture, e.g. a longer one.

## Reproducing everything from scratch

```
python certs/generate_certs.py     # once, if you haven't already
pytest tests/ -v                   # all 105 automated tests (Phases 2-7b + hash chain + evidence)
python demo/run_tamper_demo.py
python demo/run_replay_demo.py
python demo/run_mitm_handshake_demo.py
python demo/run_drop_demo.py
python demo/run_evidence_demo.py
```
