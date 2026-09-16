"""LIVE DEMO: AES-GCM (+ RSA signature) tamper detection.

Run: python demo/run_tamper_demo.py

What this proves
-----------------
Even a fully COMPROMISED RELAY SERVER -- which, after TLS terminates there,
sees the plaintext JSON chat envelope (nonce/ciphertext/tag) -- cannot alter
a single byte of a message in transit without the recipient's client
detecting it and refusing to display it. This is the AES-GCM authentication
tag doing its job (Phase 2/3): GCM is an *authenticated* cipher, so it
detects tampering, it doesn't just "encrypt" the message.

How it works
------------
This script starts a real mini relay server (the actual server.server code,
real TLS) and two real clients (the actual client.client code) that
register and complete a real, RSA-signed ECDH handshake (Phase 7a). A
`_TamperingRelay` subclass of the real ChatServer then flips one byte of the
*next* chat message's ciphertext as it relays it -- simulating a malicious
or compromised relay server tampering with a message -- and we show the
receiving client's own tamper-detection warning firing live, with the
forged content never displayed.
"""

import sys

from _demo_common import (
    banner,
    check,
    demo_username,
    establish_signed_handshake,
    free_port,
    register_client,
    run_step,
    wait_for_port,
)

import threading
from server.server import CertsMissingError, ChatServer


class _TamperingRelay(ChatServer):
    """A ChatServer that behaves exactly like the real one, except: when
    `self.tamper_next_chat` is True, the *next* "chat" envelope it relays
    has one byte of its ciphertext flipped before being forwarded -- exactly
    what a malicious or compromised relay server could attempt."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tamper_next_chat = False
        self.tampered_count = 0

    def route(self, envelope, sender_name):
        if envelope.get("type") == "chat" and self.tamper_next_chat:
            self.tamper_next_chat = False
            self.tampered_count += 1
            import base64
            raw = bytearray(base64.b64decode(envelope["ciphertext"]))
            raw[0] ^= 0xFF  # flip every bit of the first ciphertext byte
            envelope = dict(envelope)
            envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
            print(f"    [MALICIOUS RELAY] flipped a byte in this chat "
                  f"envelope's ciphertext before forwarding it.")
        super().route(envelope, sender_name)


def main():
    banner("DEMO 1: AES-GCM tamper detection (malicious relay flips a bit)")

    try:
        port = free_port()
        server = _TamperingRelay("127.0.0.1", port)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        print("[!] Run `python certs/generate_certs.py` once, then re-run this demo.")
        sys.exit(1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not wait_for_port("127.0.0.1", port, timeout=5):
        print("[!] Mini relay server never started listening.")
        sys.exit(1)
    print(f"[*] Mini (tampering-capable) relay server listening on 127.0.0.1:{port} (TLS)")

    alice_name = demo_username("alice")
    bob_name = demo_username("bob")
    print(f"[*] Demo identities for this run: {alice_name}  <-->  {bob_name}")

    alice = register_client("127.0.0.1", port, alice_name, bob_name)
    bob = register_client("127.0.0.1", port, bob_name, alice_name)
    print(f"[*] Both clients registered with fresh RSA-2048 identities.")

    ok = establish_signed_handshake(alice, bob)
    if not check(ok, "RSA-signed ECDH handshake completed on both sides.",
                 "Handshake did not complete -- aborting demo."):
        sys.exit(1)

    results = {}

    def send_normal():
        alice.send_message("This is a completely normal, untampered message.")
        import time
        time.sleep(1.0)

    _, out_normal = run_step(
        "STEP 1: alice sends a normal message -- should display correctly on bob's side",
        send_normal,
    )
    results["normal_displayed"] = "This is a completely normal, untampered message." in out_normal

    def send_tampered():
        server.tamper_next_chat = True
        alice.send_message("Transfer $1000 to Mallory's account.")
        import time
        time.sleep(1.0)

    _, out_tampered = run_step(
        "STEP 2: alice sends another message, but the (malicious) relay tampers "
        "with it in transit",
        send_tampered,
    )
    results["tampered_message_shown"] = "Transfer $1000" in out_tampered
    results["tamper_rejected"] = (
        "failed authentication" in out_tampered or "WARNING" in out_tampered
    )
    results["relay_actually_tampered"] = server.tampered_count == 1

    banner("RESULTS")
    all_ok = True
    all_ok &= check(results["normal_displayed"],
                     "Normal message displayed correctly.",
                     "Normal message was NOT displayed (unexpected failure).")
    all_ok &= check(results["relay_actually_tampered"],
                     "Confirmed the malicious relay actually flipped a byte "
                     "(this wasn't a no-op).",
                     "The relay never tampered anything -- test setup is broken.")
    all_ok &= check(not results["tampered_message_shown"],
                     "Tampered message content was NEVER displayed to bob.",
                     "TAMPERED MESSAGE WAS DISPLAYED -- tamper detection failed!")
    all_ok &= check(results["tamper_rejected"],
                     "Bob's client printed a clear tamper-detection warning.",
                     "No tamper warning was printed -- silent failure!")

    banner("DEMO 1 " + ("PASSED" if all_ok else "FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
