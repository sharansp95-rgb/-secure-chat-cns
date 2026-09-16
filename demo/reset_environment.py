"""One-command environment reset: diagnose/report a leftover server on the
configured port, then regenerate the TLS cert+key so the whole team starts a
demo from a known-clean TLS state.

Why this exists: a real bug bit the team during testing -- certs/server.crt
was regenerated on disk while an old server.py process was still running (and
still holding the *previous* cert loaded in memory), producing a confusing
CERTIFICATE_VERIFY_FAILED on any client that connected afterward. Nothing was
wrong with the code; the server process just needed a restart. This script
makes that failure mode fast to both diagnose (Part A's cert-fingerprint
printing) and avoid in the first place (this script, run before a demo).

Run:  python demo/reset_environment.py [--port 5000] [--yes]

What this does NOT do: touch data/users.json or data/keys/ -- registered
accounts and RSA identity keys are a separate concern from the TLS transport
layer and must survive a cert reset untouched.
"""

import argparse
import os
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certs.generate_certs import CERT_PATH, cert_fingerprint_from_file, generate  # noqa: E402

DEFAULT_PORT = 5000


def _port_is_listening(host, port):
    """Cross-platform baseline check, independent of netstat/lsof: True if
    something is actually accepting connections on (host, port) right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _find_pids_on_port_windows(port):
    """Parse `netstat -ano` for LISTENing PIDs on `port`. Returns a sorted
    list of ints, or None if netstat itself couldn't be run/parsed (not "no
    PIDs found" -- that's an empty list)."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None

    pids = set()
    needle = f":{port}"
    for line in result.stdout.splitlines():
        parts = line.split()
        # Typical line: TCP    127.0.0.1:5000    0.0.0.0:0    LISTENING    1234
        if len(parts) < 4:
            continue
        if parts[0].upper() not in ("TCP", "TCPV6"):
            continue
        local_addr = parts[1]
        state = parts[-2] if len(parts) >= 5 else ""
        pid_field = parts[-1]
        if local_addr.endswith(needle) and "LISTEN" in state.upper() and pid_field.isdigit():
            pids.add(int(pid_field))
    return sorted(pids)


def _find_pids_on_port_unix(port):
    """Try lsof, then fuser. Returns a sorted list of ints, or None if
    neither tool was usable (not "no PIDs found")."""
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True, text=True, timeout=10,
        )
        pids = [int(x) for x in result.stdout.split() if x.strip().isdigit()]
        if result.returncode == 0 or pids:
            return sorted(set(pids))
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        result = subprocess.run(
            ["fuser", f"{port}/tcp"], capture_output=True, text=True, timeout=10,
        )
        pids = [int(x) for x in result.stdout.split() if x.strip().isdigit()]
        return sorted(set(pids))
    except (OSError, subprocess.SubprocessError):
        return None


def find_pids_on_port(port):
    if sys.platform.startswith("win"):
        return _find_pids_on_port_windows(port)
    return _find_pids_on_port_unix(port)


def _kill_pid(pid):
    """Best-effort kill. Returns True on apparent success. Never raises --
    callers already only reach here after the user explicitly confirmed."""
    try:
        if sys.platform.startswith("win"):
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
        else:
            result = subprocess.run(
                ["kill", "-9", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def handle_port_in_use(host, port, auto_yes):
    """Report (never silently act on) anything listening on `port`. Returns
    True if the caller can proceed assuming the port is now clear, False if
    the user should go deal with it manually first."""
    if not _port_is_listening(host, port):
        print(f"[*] Port {port} is free.")
        return True

    print(f"[!] Something is already listening on {host}:{port}.")
    print("    This is very likely an old server.py process still holding the")
    print("    PREVIOUS certificate in memory -- exactly the bug this script exists")
    print("    to prevent. It needs to be restarted after the cert is regenerated.")

    pids = find_pids_on_port(port)
    if pids is None:
        print(f"[!] Could not determine which process this is (no netstat/lsof/fuser "
              f"available or the check failed).")
        print(f"    Please find and close it yourself -- e.g. the terminal window "
              f"running `python server/server.py` -- then re-run this script.")
        return False

    if not pids:
        print(f"[!] Port {port} is in use, but no matching PID could be identified.")
        print(f"    Please close whatever is using it manually, then re-run this script.")
        return False

    print(f"[!] Found PID(s) listening on port {port}: {', '.join(str(p) for p in pids)}")

    if auto_yes:
        confirmed = True
    elif not sys.stdin.isatty():
        print("[!] Not running interactively and --yes was not given -- refusing to "
              "kill anything automatically.")
        confirmed = False
    else:
        try:
            answer = input(
                f"    Kill PID(s) {', '.join(str(p) for p in pids)} now? [y/N]: "
            ).strip().lower()
        except EOFError:
            # isatty() can lie (some terminals/CI wrappers report a tty that
            # then closes stdin without ever sending a line) -- never let a
            # confirmation prompt crash the script; treat it as "no".
            print()
            answer = "n"
        confirmed = answer == "y"

    if not confirmed:
        print(f"    Not killing anything. Please stop that process yourself "
              f"(close its terminal window, or Ctrl+C it), then re-run this script.")
        return False

    all_ok = True
    for pid in pids:
        ok = _kill_pid(pid)
        print(f"    {'Killed' if ok else 'Could NOT kill'} PID {pid}.")
        all_ok = all_ok and ok

    if not all_ok:
        print("[!] At least one process could not be killed -- please close it manually.")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Reset the local TLS environment: report/optionally clear a "
                    "leftover server on the target port, then regenerate certs."
    )
    parser.add_argument("--host", default="127.0.0.1",
                         help="host to check for a listening server (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                         help="port to check (default 5000, matching server.py's default)")
    parser.add_argument("--yes", action="store_true",
                         help="don't prompt before killing a detected leftover process")
    args = parser.parse_args()

    print("=" * 70)
    print("Environment reset")
    print("=" * 70)

    print("\n--- Step 1: check for a leftover server on the target port ---")
    handle_port_in_use(args.host, args.port, args.yes)
    # Note: we proceed to regenerate certs regardless of the outcome above --
    # cert regeneration itself doesn't need the port free. What DOES matter
    # is that the user restarts the server afterward (the final message below
    # says so explicitly), so an old, still-running server is a warning, not
    # a hard blocker for this script.

    print("\n--- Step 2: regenerate TLS certificate + key ---")
    print("    (data/users.json and data/keys/ are NOT touched -- accounts and")
    print("    identity keys survive a cert reset unchanged.)")
    generate(force=True)

    fp = cert_fingerprint_from_file(CERT_PATH)
    print("\n" + "=" * 70)
    print(f"Environment reset. Cert fingerprint is now: {fp}")
    print(f"Start the server fresh with: python server/server.py")
    print(f"-- then launch clients only after you see that same fingerprint printed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
