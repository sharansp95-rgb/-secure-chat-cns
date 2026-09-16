"""LIVE DEMO: replay protection (Phase 7b).

Run: python demo/run_replay_demo.py

What this proves
-----------------
Slide claim: "nonce plus a timestamp window" stops a captured message from
being resent later and accepted again. A malicious or compromised relay
server sees the plaintext JSON envelope (nonce/ciphertext/tag) after TLS
terminates there -- so it's in a position to simply forward the *same*
envelope to the recipient a second time. This script shows that happening,
and shows the recipient's own duplicate-nonce detection catching it
immediately, with no crash and no message shown twice.

How it works
------------
Same real mini relay + real clients + real signed handshake as the other two
demos. A `_ReplayingRelay` subclass of the real ChatServer, when armed,
forwards a chat envelope to its recipient *twice* in a row -- simulating a
relay (or a network-level attacker who captured the envelope) resending it.
"""

import sys
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

import threading
from server.server import CertsMissingError, ChatServer


class _ReplayingRelay(ChatServer):
    """A ChatServer that behaves exactly like the real one, except: when
    `self.replay_next_chat` is True, the *next* "chat" envelope it relays is
    forwarded twice -- exactly what a malicious/compromised relay (or a
    network attacker resending a captured packet) could attempt."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.replay_next_chat = False
        self.replayed_count = 0

    def route(self, envelope, sender_name):
        super().route(envelope, sender_name)
        if envelope.get("type") == "chat" and self.replay_next_chat:
            self.replay_next_chat = False
            self.replayed_count += 1
            print(f"    [MALICIOUS RELAY] forwarding that SAME chat envelope "
                  f"to the recipient a second time (replay).")
            super().route(envelope, sender_name)


def main():
    banner("DEMO 2: Replay protection (relay resends a captured message)")

    try:
        port = free_port()
        server = _ReplayingRelay("127.0.0.1", port)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        print("[!] Run `python certs/generate_certs.py` once, then re-run this demo.")
        sys.exit(1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not wait_for_port("127.0.0.1", port, timeout=5):
        print("[!] Mini relay server never started listening.")
        sys.exit(1)
    print(f"[*] Mini (replay-capable) relay server listening on 127.0.0.1:{port} (TLS)")

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

    def send_replayed():
        server.replay_next_chat = True
        alice.send_message("Approve wire transfer #4471.")
        time.sleep(1.0)  # let both the original delivery AND the replay land

    _, out = run_step(
        "STEP: alice sends one message; the (malicious) relay forwards it "
        "to bob TWICE",
        send_replayed,
    )

    # The first delivery should show the message exactly once; the second,
    # replayed delivery should be caught and rejected -- not shown again.
    occurrences = out.count("Approve wire transfer #4471.")
    replay_rejected = "replay" in out.lower() and "duplicate message detected" in out

    banner("RESULTS")
    all_ok = True
    all_ok &= check(server.replayed_count == 1,
                     "Confirmed the malicious relay actually double-sent the envelope.",
                     "The relay never replayed anything -- test setup is broken.")
    all_ok &= check(occurrences == 1,
                     f"The message content was displayed exactly once ({occurrences} "
                     f"occurrence(s)), not twice.",
                     f"The message was displayed {occurrences} time(s) -- replay was "
                     f"NOT blocked!")
    all_ok &= check(replay_rejected,
                     "Bob's client printed a clear duplicate/replay rejection warning "
                     "for the second delivery.",
                     "No replay-rejection warning was printed -- silent failure!")

    banner("DEMO 2 " + ("PASSED" if all_ok else "FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
