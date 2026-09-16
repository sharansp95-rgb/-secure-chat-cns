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
```

| Script | What it proves |
|---|---|
| `run_tamper_demo.py` | A malicious/compromised relay that flips a single ciphertext byte in transit cannot get a tampered message displayed — AES-GCM's authentication tag (Phase 2/3) catches it, and the client shows a clear rejection instead of garbage. |
| `run_replay_demo.py` | A relay that captures a valid chat message and resends it a second time cannot get it displayed twice — the Phase 7b timestamp + duplicate-nonce tracking rejects the replay, even though the resent envelope is byte-for-byte identical to (and therefore passes every check that) the original valid message. |
| `run_mitm_handshake_demo.py` | A malicious relay that tries the classic unauthenticated-Diffie-Hellman attack — substituting its own ECDH public key for a peer's during the handshake — is stopped by the Phase 7a signed handshake: the victim's client derives no session key at all, and also shows that the resulting RSA key fingerprint (the human-verifiable backstop) would not have matched anyway. |

## Wireshark capture

`capture_normal_session.pcapng` (committed in this folder) is a real capture of a
normal session — registration, login, handshake, and a few chat messages — recorded on
a teammate's own machine following [`capture_instructions.md`](capture_instructions.md).
`tshark`/Wireshark wasn't available in the sandboxed environment this project was
originally *built* in, so that file documents the exact filter and steps to produce
your own capture too, e.g. a longer one, rather than relying only on the one committed
here.

## Reproducing everything from scratch

```
python certs/generate_certs.py     # once, if you haven't already
pytest tests/ -v                   # all 74 automated tests (Phases 2-7b)
python demo/run_tamper_demo.py
python demo/run_replay_demo.py
python demo/run_mitm_handshake_demo.py
```
