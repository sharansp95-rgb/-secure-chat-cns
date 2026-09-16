"""LIVE DEMO: signed handshake stops a relay-server MITM (Phase 7a).

Run: python demo/run_mitm_handshake_demo.py

What this proves
-----------------
Before Phase 7a, the ECDH handshake_init/handshake_response envelopes
carried a raw, UNSIGNED ECDH public key. A malicious or compromised relay
server -- note: this is not a network eavesdropper; TLS (Phase 6) does not
stop this, because the server itself is the trusted TLS endpoint -- could
substitute its own ECDH public key for either peer's, completing two
separate handshakes (attacker<->A, attacker<->B) while both clients believe
they're talking directly to each other. This is a classic
Diffie-Hellman-without-authentication MITM.

Since each client already has a long-term RSA identity (Phase 5), the fix
is: sign the ECDH public key with the sender's RSA private key, and have the
receiver verify that signature against the sender's RSA public key BEFORE
trusting the ECDH key enough to derive a session key from it. This script
shows a malicious relay attempting exactly the classic attack, and the
victim's client refusing to derive a session key at all.

It also demonstrates the human-facing backstop: even if some future bug let
a forged handshake slip past the automated signature check, the resulting
RSA key fingerprint the two humans would read aloud to each other would not
match -- this script prints what that mismatch would look like, for
comparison.
"""

import sys
import time

from _demo_common import (
    banner,
    check,
    demo_username,
    free_port,
    register_client,
    run_step,
    wait_for_port,
)

import threading
from client.client import b64
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair
from crypto_engine.signatures import fingerprint, generate_keypair, serialize_public_key, sign
from server.server import CertsMissingError, ChatServer


class _MitmRelay(ChatServer):
    """A ChatServer that, for ONE targeted handshake_init envelope, replaces
    the real sender's ECDH public key with the attacker's own -- signed with
    the ATTACKER's RSA key, not the real sender's -- exactly the classic
    unauthenticated-DH MITM. Everything else is relayed normally."""

    def __init__(self, *args, mitm_target_from=None, attacker_rsa_private_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.mitm_target_from = mitm_target_from
        self.attacker_rsa_private_key = attacker_rsa_private_key
        self.mitm_attempted = False

    def route(self, envelope, sender_name):
        if (
            envelope.get("type") == "handshake_init"
            and envelope.get("from") == self.mitm_target_from
            and not self.mitm_attempted
        ):
            self.mitm_attempted = True
            _, attacker_ecdh_pub = generate_ecdh_keypair()
            attacker_sig = sign(self.attacker_rsa_private_key, attacker_ecdh_pub)
            forged = dict(envelope)
            forged["pubkey"] = b64(attacker_ecdh_pub)
            forged["handshake_sig"] = b64(attacker_sig)
            print(f"    [MALICIOUS RELAY] substituted its OWN ECDH public key for "
                  f"{self.mitm_target_from}'s, signed with the ATTACKER's RSA key "
                  f"(not {self.mitm_target_from}'s) -- classic unauthenticated-DH MITM.")
            super().route(forged, sender_name)
            return
        super().route(envelope, sender_name)


def main():
    banner("DEMO 3: Signed handshake stops a relay-server MITM")

    attacker_priv, attacker_pub = generate_keypair()  # attacker never registers this key

    alice_name = demo_username("alice")
    bob_name = demo_username("bob")
    print(f"[*] Demo identities for this run: {alice_name}  <-->  {bob_name}")

    try:
        port = free_port()
        server = _MitmRelay(
            "127.0.0.1", port,
            mitm_target_from=alice_name, attacker_rsa_private_key=attacker_priv,
        )
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        print("[!] Run `python certs/generate_certs.py` once, then re-run this demo.")
        sys.exit(1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not wait_for_port("127.0.0.1", port, timeout=5):
        print("[!] Mini relay server never started listening.")
        sys.exit(1)
    print(f"[*] Mini (MITM-capable) relay server listening on 127.0.0.1:{port} (TLS)")

    alice = register_client("127.0.0.1", port, alice_name, bob_name)
    bob = register_client("127.0.0.1", port, bob_name, alice_name)
    print("[*] Both clients registered with fresh RSA-2048 identities.")

    def attempt_mitm_handshake():
        # bob needs alice's REAL public key cached to have any chance of
        # verifying correctly (this is what a real client does before
        # chatting) -- the whole point is that this correctly-configured
        # client still catches the attack.
        assert bob.fetch_peer_public_key(timeout=5)
        assert alice.fetch_peer_public_key(timeout=5)
        alice.initiate_handshake()  # this is the message the relay will intercept
        time.sleep(1.0)

    _, out = run_step(
        "STEP: alice starts a handshake with bob; the malicious relay swaps "
        "in its own ECDH key along the way",
        attempt_mitm_handshake,
    )

    attacker_fingerprint = fingerprint(serialize_public_key(attacker_pub))
    real_alice_fingerprint = fingerprint(bob.peer_public_key_pem or b"")

    banner("RESULTS")
    all_ok = True
    all_ok &= check(server.mitm_attempted,
                     "Confirmed the malicious relay actually attempted the key swap.",
                     "The relay never attempted the swap -- test setup is broken.")
    all_ok &= check(bob.session_key is None,
                     "Bob's client derived NO session key from the forged handshake "
                     "-- the MITM attempt was rejected.",
                     "BOB DERIVED A SESSION KEY FROM THE FORGED HANDSHAKE -- MITM SUCCEEDED!")
    all_ok &= check("HANDSHAKE ABORTED" in out,
                     "Bob's client printed a clear handshake-abort warning naming the "
                     "possible MITM.",
                     "No handshake-abort warning was printed -- silent failure!")

    print(f"\n[*] For comparison -- what a human reading fingerprints aloud would see:")
    print(f"    Real {alice_name}'s RSA fingerprint (what bob actually has on file):")
    print(f"        {real_alice_fingerprint}")
    print(f"    Attacker's RSA fingerprint (what would have been used if the forged")
    print(f"    handshake had used the attacker's OWN signature on THEIR OWN pubkey")
    print(f"    submission, i.e. if the attacker had also tried to register as")
    print(f"    '{alice_name}'):")
    print(f"        {attacker_fingerprint}")
    all_ok &= check(
        real_alice_fingerprint != attacker_fingerprint,
        "These fingerprints differ -- a human comparing them out-of-band (voice call, "
        "in person) would also catch this attacker, independent of any automated check.",
        "Fingerprints matched -- this comparison is broken.",
    )

    banner("DEMO 3 " + ("PASSED" if all_ok else "FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
