# Wireshark capture instructions

**Note on this artifact:** `demo/capture_normal_session.pcapng` (committed alongside
this file) is a real capture recorded on a teammate's own machine, since
Wireshark/`tshark` wasn't available in the sandboxed environment this project was
originally *built* in. This file gives the exact, copy-pasteable steps used to produce
it, so you can reproduce it yourself (e.g. a longer or different capture for the
report) rather than relying only on the one already committed here.

## What you're capturing

A normal session: **registration, login, the signed ECDH handshake, and a few chat
messages** — traffic that is now (Phase 6) wrapped in TLS, so what you'll actually see
in Wireshark is a TLS handshake followed by opaque `Application Data` records. That
absence of visible plaintext, compared to what an equivalent capture would have shown
before Phase 6, *is* the evidence — see "What to point out" below.

## Steps

1. **Generate certs** (if you haven't already) and **note the port** the server will
   listen on:
   ```
   python certs/generate_certs.py
   python server/server.py --port 5000
   ```
   (Substitute your own port below if you use a different one.)

2. **Start Wireshark** (or `tshark` from a terminal) and start a capture on your
   loopback interface:
   - Windows: capture interface **"Npcap Loopback Adapter"** (Wireshark) or
     `tshark -i \Device\NPF_Loopback -f "tcp port 5000"`.
   - macOS/Linux: interface **`lo0`**/**`lo`**, filter `tcp port 5000`.

3. **Apply the display filter** in Wireshark's filter bar:
   ```
   tcp.port == 5000
   ```
   (or `tcp.port == 5000 && tls` to see only the TLS records once the handshake is done)

4. **Run the demo session** in two more terminals, while the capture is running:
   ```
   python client/client.py --peer bob    # terminal A: register as "alice"
   python client/client.py --peer alice  # terminal B: register as "bob"
   ```
   Register both (`1) Register`), wait for `Secure session established` and the
   fingerprint lines on both sides, then type 2–3 messages back and forth.

5. **Stop the capture** and save it as:
   ```
   demo/capture_normal_session.pcapng
   ```
   (File → Save As... → Wireshark pcapng format, into this exact path so it lives
   alongside this instructions file.)

## What to point out in the capture (for your report / live demo)

- The very first packets are a **TLS handshake** (`Client Hello`, `Server Hello`,
  `Certificate`, `Finished`, ...) — click into the `Certificate` message and show the
  `CN=localhost` self-signed cert from `certs/generate_certs.py`.
- **Every packet after the handshake is `Application Data`** — Wireshark cannot parse
  it as JSON, HTTP, or anything else meaningful, because it's TLS ciphertext. Right-click
  → "Follow → TCP Stream" and show that the reassembled stream is unreadable binary, not
  `{"type": "register", ...}` — this is the direct, visual proof that Phase 6 closed the
  plaintext register/login gap Phases 4–5 had flagged.
- Contrast this with what the **same capture would have shown before Phase 6** (you can
  demonstrate this live by temporarily pointing `client.py`/`server.py` at a raw,
  unwrapped socket, or simply describe it): every envelope, including `"type": "login"`
  and the password field, would have been plainly visible in "Follow TCP Stream".
- You will **not** be able to show the individual `register`/`login`/`handshake_init`/
  `chat` JSON envelopes inside the capture itself, by design — that's the point of TLS.
  To show *those* structures for the report, use the plaintext-envelope tables already
  in the main [README.md](../README.md#wire-protocol) instead, or the
  `demo/run_*.py` scripts' printed output, which display the real envelope contents
  from inside the code (where they're briefly in the clear, before TLS/encryption)
  rather than trying to read them off the wire.
