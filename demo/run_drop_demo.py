"""LIVE DEMO: hash-chained conversation log detects a silently DROPPED message.

Run: python demo/run_drop_demo.py

What this proves
-----------------
AES-GCM and RSA signatures prove each message is authentic -- but they say
nothing about messages that NEVER ARRIVE. A malicious relay can simply drop a
perfectly valid message ("Do NOT administer the second dose") and every
message that does arrive still verifies. Plain per-message security cannot
see that.

The hash chain can. Every message carries a per-sender sequence number and
the hash of the sender's previous message, all inside the signed + encrypted
payload (so the relay can neither read nor forge them). When message #3
arrives where #2 was expected, the receiver knows something was removed.

How it works
------------
Real mini relay (the actual server.server code, real TLS) subclassed to drop
exactly one chat envelope, and two real clients doing a real RSA-signed ECDH
handshake -- no mocks. alice sends three messages; the relay drops the second.
"""

import sys
import threading
import time

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

from server.server import CertsMissingError, ChatServer


class _DroppingRelay(ChatServer):
    """Behaves exactly like the real server, except it silently swallows the
    next chat envelope when `drop_next_chat` is set -- no error to either
    side, as a malicious relay would."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.drop_next_chat = False
        self.dropped_count = 0

    def route(self, envelope, sender_name):
        if envelope.get("type") == "chat" and self.drop_next_chat:
            self.drop_next_chat = False
            self.dropped_count += 1
            print("    [MALICIOUS RELAY] silently dropped a valid chat message "
                  "(it is never forwarded, and nobody is told).")
            return
        super().route(envelope, sender_name)


def main():
    banner("DEMO 4: hash-chained log detects a message silently dropped by the relay")

    try:
        port = free_port()
        server = _DroppingRelay("127.0.0.1", port)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        print("[!] Run `python certs/generate_certs.py` once, then re-run this demo.")
        sys.exit(1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not wait_for_port("127.0.0.1", port, timeout=5):
        print("[!] Mini relay server never started listening.")
        sys.exit(1)
    print(f"[*] Mini (dropping-capable) relay server listening on 127.0.0.1:{port} (TLS)")

    alice_name = demo_username("alice")
    bob_name = demo_username("bob")
    print(f"[*] Demo identities for this run: {alice_name}  <-->  {bob_name}")

    alice = register_client("127.0.0.1", port, alice_name, bob_name)
    bob = register_client("127.0.0.1", port, bob_name, alice_name)
    print("[*] Both clients registered with fresh RSA-2048 identities.")

    ok = establish_signed_handshake(alice, bob)
    if not check(ok, "RSA-signed ECDH handshake completed on both sides.",
                 "Handshake did not complete -- aborting demo."):
        sys.exit(1)

    def send(text, drop=False):
        server.drop_next_chat = drop
        alice.send_message(text)
        time.sleep(1.0)

    _, out1 = run_step("STEP 1: alice sends message #1 -- delivered normally",
                       lambda: send("Patient 4411: start 5mg."))
    _, out2 = run_step("STEP 2: alice sends message #2 -- but the relay silently DROPS it",
                       lambda: send("Patient 4411: STOP, allergic reaction.", drop=True))
    _, out3 = run_step("STEP 3: alice sends message #3 -- delivered; bob's chain check fires",
                       lambda: send("Patient 4411: confirm you received my last order."))

    banner("RESULTS")
    all_ok = True
    all_ok &= check("start 5mg" in out1 and "WARNING" not in out1,
                    "Message #1 displayed with no warning.",
                    "Message #1 was not displayed cleanly.")
    all_ok &= check(server.dropped_count == 1,
                    "Confirmed the relay really dropped message #2 (not a no-op).",
                    "The relay never dropped anything -- demo setup is broken.")
    all_ok &= check("STOP, allergic" not in out2 + out3,
                    "The dropped message never reached bob (the attack worked at the "
                    "network level).",
                    "The dropped message somehow arrived.")
    all_ok &= check("1 message(s) missing" in out3
                    and "possible deletion by the relay" in out3,
                    "Bob's client detected the gap: '1 message(s) missing ... "
                    "possible deletion by the relay'.",
                    "NO gap warning was printed -- the drop went undetected!")
    all_ok &= check("confirm you received" in out3,
                    "The authentic message #3 was still delivered (flagged, not lost).",
                    "Message #3 was not delivered.")
    all_ok &= check(any(e["reason"] == "chain_gap" for e in bob.rejected_events),
                    "The gap was recorded in bob's rejected-events list for the "
                    "evidence export.",
                    "The gap was not recorded for the evidence export.")

    banner("DEMO 4 " + ("PASSED" if all_ok else "FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
