"""demo/reset_environment.py must only ever kill OUR server.py.

macOS's AirPlay Receiver (ControlCenter) also listens on port 5000, and the
script used to `kill -9` every PID it found on the port when run with --yes.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo"))

import reset_environment as reset  # noqa: E402

OURS = ".venv/bin/python -u server/server.py --port 5000"
AIRPLAY = "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"


def _setup(monkeypatch, commands):
    killed = []
    monkeypatch.setattr(reset, "_port_is_listening", lambda host, port: True)
    monkeypatch.setattr(reset, "find_pids_on_port", lambda port: list(commands))
    monkeypatch.setattr(reset, "_command_line", lambda pid: commands.get(pid))
    monkeypatch.setattr(reset, "_kill_pid", lambda pid: killed.append(pid) or True)
    return killed


def test_only_our_server_is_killed_never_airplay(monkeypatch):
    killed = _setup(monkeypatch, {111: OURS, 222: AIRPLAY})
    assert reset.handle_port_in_use("127.0.0.1", 5000, auto_yes=True) is True
    assert killed == [111]


def test_foreign_listener_alone_is_left_alone_and_does_not_block(monkeypatch):
    killed = _setup(monkeypatch, {222: AIRPLAY})
    assert reset.handle_port_in_use("127.0.0.1", 5000, auto_yes=True) is True
    assert killed == []


def test_unreadable_command_line_is_treated_as_not_ours(monkeypatch):
    killed = _setup(monkeypatch, {333: None})
    assert reset.handle_port_in_use("127.0.0.1", 5000, auto_yes=True) is True
    assert killed == []
