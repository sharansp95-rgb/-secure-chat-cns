"""The demo/run_*.py scripts must never touch the real data/ (users.json, private keys), logs/
or exports/: they register throwaway users, so they work in a temporary directory that is
removed afterwards. (The live GUI demo, demo/start_demo.sh, is the one that uses the real data/.)

These tests hash the real folders byte-for-byte before and after actually running scripts."""

import hashlib
import os
import subprocess
import sys

import pytest

from conftest import ROOT

REAL_FOLDERS = ("data", "logs", "exports")


def tree_hash(root):
    """SHA-256 over every file (relative path + bytes) under the real data/, logs/, exports/."""
    digest = hashlib.sha256()
    for folder in REAL_FOLDERS:
        base = os.path.join(root, folder)
        for dirpath, _dirs, files in sorted(os.walk(base)):
            for name in sorted(files):
                path = os.path.join(dirpath, name)
                digest.update(os.path.relpath(path, root).encode())
                with open(path, "rb") as f:
                    digest.update(f.read())
    return digest.hexdigest()


def run_demo(script):
    return subprocess.run([sys.executable, os.path.join("demo", script)], cwd=ROOT,
                          capture_output=True, text=True, timeout=180)


@pytest.mark.parametrize("script", ["run_tamper_demo.py", "run_evidence_demo.py"])
def test_demo_scripts_leave_the_real_data_logs_and_exports_untouched(script):
    before = tree_hash(ROOT)
    proc = run_demo(script)
    after = tree_hash(ROOT)
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    assert before == after, f"{script} changed data/, logs/ or exports/"


def test_the_isolation_helper_redirects_everything_and_cleans_up(tmp_path):
    code = (
        "import sys, os; sys.path.insert(0, 'demo'); sys.path.insert(0, '.');"
        "import _demo_common as dc, server.server as sm, client.evidence as ev;"
        "root = dc.isolate_demo_state();"
        "assert root and os.path.isdir(root), root;"
        "assert dc.isolate_demo_state() == root;"                       # idempotent
        "assert ev.DEFAULT_EXPORT_DIR.startswith(root), ev.DEFAULT_EXPORT_DIR;"
        "assert sm.register_user.keywords['path'].startswith(root);"
        "assert dc.save_private_key.keywords['keys_dir'].startswith(root);"
        "print(root)"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert not os.path.exists(proc.stdout.strip()), "the temp directory is removed at exit"


def test_every_demo_script_calls_the_isolation_helper():
    demo_dir = os.path.join(ROOT, "demo")
    scripts = [f for f in os.listdir(demo_dir) if f.startswith("run_") and f.endswith(".py")]
    assert len(scripts) >= 6
    for name in scripts:
        source = open(os.path.join(demo_dir, name)).read()
        assert "isolate_demo_state" in source, f"{name} does not isolate its state"
