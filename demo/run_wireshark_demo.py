#!/usr/bin/env python3
"""Automated Wireshark demo: starts tshark capture, runs a real chat session
(register two users, ECDH handshake, exchange messages), stops capture,
and saves the .pcapng file.

Usage:
    python demo/run_wireshark_demo.py
    python demo/run_wireshark_demo.py --open-wireshark   # opens the capture in Wireshark GUI after

Requires:
    - Wireshark installed (tshark is used for capture)
    - Project certs generated (python certs/generate_certs.py)
    - Virtual environment with requirements installed

What this does:
    1. Starts a mini relay server on a free ephemeral port, with a TEMPORARY user
       store, key directory and security log (your real data/ is never touched)
    2. Starts tshark capture on loopback for that port
    3. Registers "alice" (sender) and "bob" (receiver)
    4. Performs the signed ECDH handshake
    5. Alice sends 3 messages to Bob, Bob replies with 2
    6. Stops capture and saves to demo/wireshark_capture.pcapng
    7. Verifies the TLS 1.3 handshake is in the capture and scans the RAW bytes for
       any plaintext (usernames, password, message text, JSON field names)
    8. Optionally opens the capture in Wireshark GUI
"""

import argparse
import functools
import os
import shutil
import tempfile
import signal
import subprocess
import sys
import threading
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import demo._demo_common as demo_common
import server.security_log as security_log
import server.server as server_module
from demo._demo_common import (
    DEMO_PASSWORD,
    banner,
    check,
    demo_username,
    establish_signed_handshake,
    free_port,
    register_client,
    start_mini_relay,
    wait_for_port,
)

# ---------- Paths ----------
TSHARK_PATHS = [
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
    shutil.which("tshark") or "",
]
WIRESHARK_PATHS = [
    "/Applications/Wireshark.app",
    "/usr/local/bin/wireshark",
    shutil.which("wireshark") or "",
]
CAPTURE_FILE = os.path.join(PROJECT_ROOT, "demo", "wireshark_capture.pcapng")

# macOS loopback interface
LOOPBACK_IFACE = "lo0"


def isolate_state():
    """Point the relay's user store, the security log and the client key store at a
    throwaway directory, so this script never adds accounts to (or writes into) the
    real data/ and logs/. Returns the directory; the caller deletes it."""
    root = tempfile.mkdtemp(prefix="securechat_wireshark_demo_")
    store = os.path.join(root, "users.json")
    keys_dir = os.path.join(root, "keys")
    log_path = os.path.join(root, "security_events.jsonl")
    for name in ("register_user", "verify_user", "get_public_key"):
        setattr(server_module, name, functools.partial(getattr(server_module, name), path=store))
    real_log_event = security_log.log_event
    server_module.log_event = lambda event, **fields: real_log_event(event, path=log_path, **fields)
    demo_common.save_private_key = functools.partial(demo_common.save_private_key, keys_dir=keys_dir)
    return root


def plaintext_scan(capture_file, needles):
    """Search the RAW capture bytes for each needle (str or bytes). Returns the
    needles that were found -- an empty list means nothing leaked."""
    with open(capture_file, "rb") as f:
        raw = f.read()
    return [n for n in needles
            if (n.encode("utf-8") if isinstance(n, str) else n) in raw]


def find_tshark():
    for p in TSHARK_PATHS:
        if p and os.path.exists(p):
            return p
    return None


def find_wireshark():
    for p in WIRESHARK_PATHS:
        if p and os.path.exists(p):
            return p
    return None


def start_tshark_capture(port, output_file):
    """Start tshark capturing on loopback for the given port."""
    tshark = find_tshark()
    if not tshark:
        print("[!] tshark not found. Install Wireshark first.")
        print("    On macOS: brew install --cask wireshark")
        sys.exit(1)

    cmd = [
        tshark,
        "-i", LOOPBACK_IFACE,
        "-f", f"tcp port {port}",
        "-w", output_file,
        "-q",  # quiet mode
    ]
    print(f"[*] Starting capture: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Give tshark a moment to start capturing
    time.sleep(2)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode()
        print(f"[!] tshark failed to start: {stderr}")
        if "permission" in stderr.lower() or "privileges" in stderr.lower():
            print("[!] Try running with sudo, or grant Wireshark capture permissions:")
            print("    sudo chmod +x /dev/bpf*")
            print("    Or: open Wireshark GUI once and grant access when prompted")
        sys.exit(1)
    print(f"[*] tshark is capturing on {LOOPBACK_IFACE}, filter: tcp port {port}")
    return proc


def stop_tshark_capture(proc):
    """Stop tshark gracefully and return packet count."""
    proc.send_signal(signal.SIGINT)
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    output = stderr.decode() if stderr else ""
    # tshark prints packet count to stderr like "N packets captured"
    packet_count = 0
    for line in output.splitlines():
        if "packet" in line.lower():
            parts = line.strip().split()
            for p in parts:
                if p.isdigit():
                    packet_count = int(p)
                    break
    return packet_count, output


def analyze_capture(capture_file, port, needles=()):
    """Use tshark to analyze the capture and show protocol breakdown."""
    tshark = find_tshark()
    if not tshark:
        return ["tshark not found"]

    print(f"\n{'─' * 60}")
    print("CAPTURE ANALYSIS")
    print(f"{'─' * 60}")

    # Show protocol hierarchy
    try:
        result = subprocess.run(
            [tshark, "-r", capture_file, "-q", "-z", "io,phs",
             "-d", f"tcp.port=={port},tls"],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout:
            print("\n📊 Protocol Hierarchy:")
            print(result.stdout)
    except Exception as e:
        print(f"    (protocol hierarchy unavailable: {e})")

    # Show TLS handshake details
    try:
        result = subprocess.run(
            [tshark, "-r", capture_file,
             "-d", f"tcp.port=={port},tls",
             "-Y", "tls.handshake",
             "-T", "fields",
             "-e", "tls.handshake.type",
             "-e", "tls.handshake.version",
             "-e", "tls.handshake.ciphersuite"],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout.strip():
            print("🔒 TLS Handshake Records Found:")
            for line in result.stdout.strip().splitlines():
                print(f"    {line}")
    except Exception:
        pass

    # Count Application Data records (encrypted payload)
    try:
        result = subprocess.run(
            [tshark, "-r", capture_file,
             "-d", f"tcp.port=={port},tls",
             "-Y", "tls.app_data"],
            capture_output=True, text=True, timeout=10,
        )
        app_data_count = len(result.stdout.strip().splitlines()) if result.stdout.strip() else 0
        print(f"\n🔐 Encrypted Application Data records: {app_data_count}")
    except Exception:
        pass

    # Prove the handshake really is TLS 1.3: a Client Hello (type 1) and a Server
    # Hello (type 2) whose supported_versions extension is 0x0304.
    problems = []
    try:
        result = subprocess.run(
            [tshark, "-r", capture_file, "-d", f"tcp.port=={port},tls",
             "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2", "-T", "fields",
             "-e", "tls.handshake.type", "-e", "tls.handshake.extensions.supported_version"],
            capture_output=True, text=True, timeout=10)
        hellos = [ln.split("\t") for ln in result.stdout.strip().splitlines()]
        client_hellos = sum(1 for h in hellos if h[0] == "1")
        tls13_server_hellos = sum(1 for h in hellos if h[0] == "2" and "0x0304" in h[-1])
        print(f"\n🔎 Client Hellos: {client_hellos}   TLS 1.3 Server Hellos: {tls13_server_hellos}")
        if client_hellos < 1 or tls13_server_hellos < 1:
            problems.append("TLS 1.3 handshake (Client Hello + Server Hello) not found in capture")
    except Exception as e:
        problems.append(f"could not inspect the handshake: {e}")

    # Scan the RAW bytes of the capture for anything that should be encrypted.
    leaked = plaintext_scan(capture_file, needles)
    print(f"\n🕵  Plaintext scan of the raw capture: {len(needles)} strings searched "
          f"(usernames, password, message text, JSON field names)")
    if leaked:
        print(f"⚠️  WARNING: found in plaintext: {leaked}")
        problems.append(f"plaintext found: {leaked}")
    else:
        print("✅ None of them appear anywhere in the capture bytes — all data is TLS-encrypted!")

    print(f"\n📁 Capture saved to: {capture_file}")
    print(f"   File size: {os.path.getsize(capture_file):,} bytes")
    return problems


def open_in_wireshark(capture_file, port):
    """Open the capture in the Wireshark GUI with the demo port decoded as TLS and
    the display filter set to `tls` (a random port would otherwise be shown as plain TCP)."""
    ws = find_wireshark()
    if not ws:
        print("[!] Wireshark GUI not found, skipping open")
        return
    args = ["-d", f"tcp.port=={port},tls", "-Y", "tls", "-r", capture_file]
    if ws.endswith(".app"):
        subprocess.Popen(["open", "-n", "-a", ws, "--args"] + args)
    else:
        subprocess.Popen([ws] + args)
    print(f"[*] Opened {capture_file} in Wireshark (port {port} decoded as TLS, filter: tls)")


def main():
    parser = argparse.ArgumentParser(description="Automated Wireshark capture demo")
    parser.add_argument("--open-wireshark", action="store_true",
                        help="Open capture in Wireshark GUI when done")
    parser.add_argument("--output", default=CAPTURE_FILE,
                        help=f"Output capture file (default: {CAPTURE_FILE})")
    args = parser.parse_args()

    banner("WIRESHARK DEMO — Automated Secure Chat Capture")
    print("This script will:")
    print("  1. Start a TLS relay server")
    print("  2. Start tshark capture on loopback")
    print("  3. Register Sender (alice) & Receiver (bob)")
    print("  4. Perform the ECDH key exchange")
    print("  5. Exchange encrypted messages")
    print("  6. Stop capture and analyze the traffic")
    print()

    state_dir = isolate_state()
    print(f"[*] Using a temporary data directory (deleted at the end): {state_dir}")

    # ── Step 1: Start server ──
    print("━" * 50)
    print("STEP 1: Starting relay server")
    print("━" * 50)
    server, host, port = start_mini_relay()

    # ── Step 2: Start capture ──
    print(f"\n{'━' * 50}")
    print("STEP 2: Starting tshark capture")
    print("━" * 50)
    tshark_proc = start_tshark_capture(port, args.output)

    # Small delay to ensure capture is ready before any traffic
    time.sleep(1)

    try:
        # ── Step 3: Register users ──
        print(f"\n{'━' * 50}")
        print("STEP 3: Registering Sender (alice) and Receiver (bob)")
        print("━" * 50)
        alice_name = demo_username("alice")
        bob_name = demo_username("bob")
        print(f"    Sender  : {alice_name}")
        print(f"    Receiver: {bob_name}")

        alice = register_client(host, port, alice_name, bob_name)
        print(f"    ✓ Sender ({alice_name}) registered")

        bob = register_client(host, port, bob_name, alice_name)
        print(f"    ✓ Receiver ({bob_name}) registered")

        # ── Step 4: ECDH handshake ──
        print(f"\n{'━' * 50}")
        print("STEP 4: Performing signed ECDH key exchange")
        print("━" * 50)
        ok = establish_signed_handshake(alice, bob, timeout=10)
        if ok:
            print("    ✓ Secure session established (ECDH + signatures)")
            check(alice.session_key == bob.session_key,
                  "Both sides derived the same session key",
                  "Session keys don't match!")
        else:
            print("    ✗ Handshake failed!")
            sys.exit(1)

        # ── Step 5: Exchange messages ──
        print(f"\n{'━' * 50}")
        print("STEP 5: Exchanging encrypted messages")
        print("━" * 50)

        messages_to_send = [
            (alice, "Hello Bob! This is a secret message from Alice. 🔒"),
            (bob,   "Hi Alice! I received your message securely. 🛡️"),
            (alice, "Great! Our communication is end-to-end encrypted."),
            (bob,   "Yes! Even with Wireshark, nobody can read this."),
            (alice, "Final test message — CNS Project Demo complete! 🎓"),
        ]

        for sender, msg in messages_to_send:
            sender_label = "Sender (alice)" if sender is alice else "Receiver (bob)"
            print(f"    📨 {sender_label}: \"{msg}\"")
            sender.send_message(msg)
            time.sleep(0.5)  # Let the message travel through TLS

        # Wait a bit for all messages to be delivered
        time.sleep(2)

        print(f"\n    ✓ {len(messages_to_send)} messages exchanged over encrypted channel")

    finally:
        # ── Step 6: Stop capture ──
        print(f"\n{'━' * 50}")
        print("STEP 6: Stopping capture and analyzing traffic")
        print("━" * 50)
        packet_count, tshark_output = stop_tshark_capture(tshark_proc)
        print(f"    Captured {packet_count} packets" if packet_count else
              f"    Capture stopped. tshark output:\n    {tshark_output.strip()}")

    # ── Analysis ──
    problems = []
    if os.path.exists(args.output) and os.path.getsize(args.output) > 0:
        needles = [alice_name, bob_name, DEMO_PASSWORD, "password", "register", "username",
                   '"type"', '"nonce"', '"ciphertext"', '"public_key"', '"message"',
                   '"sender"', '"signature"'] + [m for _s, m in messages_to_send]
        problems = analyze_capture(args.output, port, needles)
    else:
        problems = ["capture file empty or missing"]
        print(f"\n[!] Capture file is empty or missing: {args.output}")
        print("    This usually means tshark couldn't capture on the loopback interface.")
        print("    Try: sudo python demo/run_wireshark_demo.py")

    shutil.rmtree(state_dir, ignore_errors=True)

    # ── Open in Wireshark ──
    if args.open_wireshark:
        open_in_wireshark(args.output, port)

    if problems:
        print(f"\n[!] CHECKS FAILED: {problems}")
        sys.exit(1)

    banner("DEMO COMPLETE")
    print(f"""
SUMMARY
{'─' * 50}
  ✓ Server ran on 127.0.0.1:{port} over TLS 1.3
  ✓ Sender (alice) and Receiver (bob) registered
  ✓ ECDH key exchange completed with signatures
  ✓ {len(messages_to_send)} encrypted messages exchanged
  ✓ All traffic captured to: {args.output}
  ✓ No plaintext visible in capture — TLS encrypts everything

WHAT TO SHOW IN YOUR DEMO / REPORT:
{'─' * 50}
  1. Open {args.output} in Wireshark
  2. Set display filter:  tcp.port == {port}
  3. If protocol shows 'RSL', right-click → Decode As → TLS
  4. Point out:
     • TLS 1.3 Client Hello / Server Hello packets
     • All chat data is "Application Data" (unreadable ciphertext)
     • Right-click → Follow → TCP Stream → shows binary gibberish
     • Compare with what plaintext JSON would look like
""")


if __name__ == "__main__":
    main()
