"""LIVE DEMO: signed evidence export + independent offline verification.

Run: python demo/run_evidence_demo.py

What this proves (NON-REPUDIATION, the opposite of WhatsApp/Signal's deniability)
-----------------------------------------------------------------------------
Two real clients hold a short conversation through a real TLS relay. One of
them exports a signed EVIDENCE FILE. A third party then verifies it with
tools/verify_transcript.py -- a separate program that imports no client or
server code -- and learns, without trusting either user or the server:

  * who said each message (RSA signature by that person's identity key),
  * that nothing was dropped, reordered or edited (hash chain),
  * that the export itself was not altered afterwards (exporter signature).

Then we change ONE WORD in ONE message of a copy of that file and verify
again: INVALID, and the verifier names the exact message and the failed check.
"""

import copy
import json
import os
import subprocess
import sys
import time

from _demo_common import (
    PROJECT_ROOT,
    banner,
    check,
    demo_username,
    establish_signed_handshake,
    register_client,
    run_step,
    start_mini_relay,
)

VERIFIER = os.path.join(PROJECT_ROOT, "tools", "verify_transcript.py")
EXPORT_DIR = os.path.join(PROJECT_ROOT, "exports")


def run_verifier(path, *extra):
    proc = subprocess.run([sys.executable, VERIFIER, path, *extra],
                          capture_output=True, text=True)
    print(proc.stdout.rstrip())
    return proc.returncode, proc.stdout


def main():
    banner("DEMO 5: signed evidence export + independent offline verifier")

    _, host, port = start_mini_relay()
    alice_name = demo_username("alice")
    bob_name = demo_username("bob")
    print(f"[*] Demo identities for this run: {alice_name}  <-->  {bob_name}")
    alice = register_client(host, port, alice_name, bob_name)
    bob = register_client(host, port, bob_name, alice_name)
    if not check(establish_signed_handshake(alice, bob),
                 "RSA-signed ECDH handshake completed on both sides.",
                 "Handshake did not complete -- aborting demo."):
        sys.exit(1)

    def converse():
        for sender, text in [
            (alice, "Approve the transfer of $500 to Acme Ltd."),
            (bob, "Approved, reference 7731."),
            (alice, "Thanks, executing it now."),
            (bob, "Confirmed on my side."),
        ]:
            sender.send_message(text)
            time.sleep(0.6)

    run_step("STEP 1: a short real conversation (4 messages, both directions)", converse)

    def export():
        path = bob.export_evidence(EXPORT_DIR)
        print(f"[*] {bob_name} exported signed evidence to: "
              f"{os.path.relpath(path, PROJECT_ROOT)}")
        return path

    path, _ = run_step("STEP 2: bob exports a signed evidence file", export)

    print("\n--- STEP 3: an auditor verifies the file with the INDEPENDENT tool "
          "(python tools/verify_transcript.py) ---")
    rc_good, out_good = run_verifier(path)

    print("\n--- STEP 4: someone changes ONE WORD in ONE message of a copy, "
          "then the auditor verifies that copy ---")
    with open(path, encoding="utf-8") as f:
        evidence = json.load(f)
    tampered = copy.deepcopy(evidence)
    target = next(i for i, r in enumerate(tampered["records"], start=1)
                  if "Approve the transfer" in r["message"])
    tampered["records"][target - 1]["message"] = \
        tampered["records"][target - 1]["message"].replace("Approve", "Reject")
    print(f"[*] Edited record #{target}: "
          f"\"{evidence['records'][target - 1]['message']}\"  ->  "
          f"\"{tampered['records'][target - 1]['message']}\"")
    tampered_path = path.replace(".json", ".TAMPERED.json")
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(tampered, f, indent=2, ensure_ascii=False)
    rc_bad, out_bad = run_verifier(tampered_path)

    banner("RESULTS")
    all_ok = True
    all_ok &= check(rc_good == 0 and "RESULT: VALID" in out_good,
                    "The genuine export verifies as VALID.",
                    "The genuine export did NOT verify -- something is broken!")
    all_ok &= check(rc_bad == 1 and "RESULT: INVALID" in out_bad,
                    "The one-word edit makes the copy INVALID.",
                    "The tampered copy was accepted -- non-repudiation is broken!")
    all_ok &= check(f"record #{target}" in out_bad and "signature" in out_bad,
                    f"The verifier names the exact message (record #{target}) and the "
                    f"failed check (signature).",
                    "The verifier did not point at the edited message.")

    banner("DEMO 5 " + ("PASSED" if all_ok else "FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
