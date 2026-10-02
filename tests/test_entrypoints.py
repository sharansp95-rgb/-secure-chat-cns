"""The documented ways of starting the project must actually start.

`python server/server.py` runs the file as a SCRIPT, which changes how
`import server...` resolves (the script's own directory lands on sys.path, so
`server` can mean server/server.py itself instead of the package). Every other
test imports the code as a package, so a script-mode-only import failure --
which really did ship once, breaking `python server/server.py --lab` -- is
invisible to them. These tests launch the entry points in subprocesses,
exactly as a user would.
"""

import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_script(*args, timeout=30):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout)


@pytest.mark.parametrize("script", ["server/server.py", "client/client.py",
                                    "gui/security_dashboard.py", "gui/chat_gui.py"])
def test_cli_entry_point_starts_in_script_mode(script):
    result = run_script(script, "--help")
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_server_script_actually_serves_with_lab_mode():
    """Not just --help: start `python server/server.py --lab --port 0` for
    real, wait for its startup banner, then stop it."""
    proc = subprocess.Popen([sys.executable, "-u", "server/server.py", "--port", "0", "--lab"],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        lines = []
        deadline = time.time() + 30
        while time.time() < deadline and not any("LAB MODE ENABLED" in l for l in lines):
            line = proc.stdout.readline()
            if not line:
                break  # process exited early: fall through to the assertions
            lines.append(line)
        output = "".join(lines)
        assert "Server listening on 127.0.0.1:" in output, output
        assert "cert fingerprint:" in output
        assert "LAB MODE ENABLED" in output, output
    finally:
        proc.terminate()
        proc.wait(timeout=10)
