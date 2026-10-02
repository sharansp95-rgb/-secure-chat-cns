#!/usr/bin/env python3
"""Security and performance evaluation of the Secure Chat implementation.

    python tools/evaluate_security.py            # full run (a few minutes)
    python tools/evaluate_security.py --quick    # short run (about a minute)
    python tools/evaluate_security.py --show     # re-print the last saved summary

Evaluation ONLY: nothing here adds a feature or changes protocol or crypto
behaviour; it drives the real code and measures it. It produces measured
evidence for the course's evaluation criteria (encryption/decryption,
authentication, integrity, resistance to common attacks, overall security
effectiveness) and for the Review 1 non-functional requirement "encryption
overhead small enough for real-time chat (< 1 s)".

  1. Functional verification   the pytest suite, grouped by area
  2. Attack resistance         each attack N times through the real lab-mode
                               relay (tamper, replay, drop, MITM key swap), plus
                               edited evidence files and wrong-password bursts,
                               and normal traffic to measure false rejections
  3. Performance overhead      median / 95th percentile for every crypto
                               primitive and for end-to-end message latency and
                               session setup through the real TLS server

Isolation: everything runs against a local server (OS-chosen port, lab mode)
with a TEMPORARY data directory, key store, security log and exports folder.
The real data/ is never touched (its SHA-256 is compared before and after) and
all temporary files are deleted at the end.

Writes docs/evaluation_results.md and docs/evaluation_results.json.
"""

import argparse
import functools
import hashlib
import json
import math
import os
import platform
import random
import shutil
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import client.client as client_module  # noqa: E402
import server.server as server_module  # noqa: E402
import verify_transcript  # noqa: E402
from auth.password_hash import MIN_ITERATIONS, hash_password, verify_password  # noqa: E402
from client.client import SecureChatClient, connect_tls  # noqa: E402
from crypto_engine.aes_gcm import decrypt, encrypt, generate_key  # noqa: E402
from crypto_engine.dh_exchange import compute_shared_key  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import serialize_public_key, sign, verify  # noqa: E402
from server.lockout import LockoutGuard  # noqa: E402
from server.security_log import log_event as real_log_event  # noqa: E402
from server.security_log import read_events  # noqa: E402

HOST = "127.0.0.1"
PASSWORD = "Eval-Password-1234!"
REQUIREMENT_MS = 1000.0            # Review 1: encryption overhead < 1 s
OUT = sys.stdout                   # real stdout (the experiments silence sys.stdout)
DEVNULL = open(os.devnull, "w")

# Which test files belong to which area of the functional-verification table.
AREAS = [
    ("AES-256-GCM encryption/decryption", ["test_aes_gcm"]),
    ("ECDH handshake (signed)", ["test_dh_exchange", "test_handshake_auth"]),
    ("Password hashing + lockout", ["test_password_hash", "test_lockout", "test_security_events"]),
    ("RSA signatures (non-repudiation)", ["test_signatures"]),
    ("TLS transport", ["test_tls_setup"]),
    ("Replay protection", ["test_replay_protection"]),
    ("Hash-chained log", ["test_hash_chain"]),
    ("Evidence export + verifier", ["test_evidence_export"]),
    ("Attack Lab", ["test_attack_lab"]),
]


def say(message=""):
    print(message, file=OUT, flush=True)


def silenced():
    """The clients and server print progress lines; keep them out of the report."""
    class _Quiet:
        def __enter__(self):
            self.saved, sys.stdout = sys.stdout, DEVNULL

        def __exit__(self, *exc):
            sys.stdout = self.saved
    return _Quiet()


# =============================================================================
# statistics and tables
# =============================================================================

def percentile(sorted_values, q):
    """Nearest-rank percentile (q in 0..100) of an ascending list."""
    if not sorted_values:
        return float("nan")
    rank = max(1, math.ceil(q / 100.0 * len(sorted_values)))
    return sorted_values[rank - 1]


def summarize(values_ms):
    v = sorted(values_ms)
    return {"n": len(v), "median_ms": statistics.median(v), "p95_ms": percentile(v, 95),
            "mean_ms": statistics.fmean(v), "min_ms": v[0], "max_ms": v[-1]}


def fmt_ms(x):
    return f"{x:.3f}" if x < 10 else f"{x:.1f}"


def pct(num, den):
    return f"{100.0 * num / den:.1f}%" if den else "n/a"


def text_table(headers, rows):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    line = lambda r: "  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip()  # noqa: E731
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in rows])


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# =============================================================================
# machine info and real-data guard
# =============================================================================

def machine_info():
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        try:
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                 text=True, timeout=5).stdout.strip() or cpu
        except (OSError, subprocess.SubprocessError):
            pass
    import Crypto
    import cryptography
    return {
        "cpu": cpu, "cores": os.cpu_count(), "machine": platform.machine(),
        "os": f"{platform.system()} {platform.release()} ({platform.platform()})",
        "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
        "cryptography": cryptography.__version__, "pycryptodome": Crypto.__version__,
        "pbkdf2_iterations": MIN_ITERATIONS,
    }


def tree_hash(path):
    """SHA-256 over every file (name + bytes) under `path`; 'absent' if missing."""
    if not os.path.isdir(path):
        return "absent"
    digest = hashlib.sha256()
    for dirpath, _dirs, files in sorted(os.walk(path)):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            digest.update(os.path.relpath(full, path).encode())
            with open(full, "rb") as f:
                digest.update(f.read())
    return digest.hexdigest()


# =============================================================================
# 1. functional verification
# =============================================================================

def run_functional(tmp):
    junit = os.path.join(tmp, "junit.xml")
    started = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider",
         "--junitxml", junit], cwd=ROOT, capture_output=True, text=True)
    duration = time.time() - started
    counts = {}
    for case in ET.parse(junit).getroot().iter("testcase"):
        module = case.get("classname", "").split(".")[1] if "." in case.get("classname", "") else ""
        entry = counts.setdefault(module, {"passed": 0, "failed": 0, "skipped": 0})
        if case.find("failure") is not None or case.find("error") is not None:
            entry["failed"] += 1
        elif case.find("skipped") is not None:
            entry["skipped"] += 1
        else:
            entry["passed"] += 1
    rows, claimed = [], set()
    for area, modules in AREAS:
        c = {"passed": 0, "failed": 0, "skipped": 0}
        for m in modules:
            claimed.add(m)
            for k in c:
                c[k] += counts.get(m, {}).get(k, 0)
        rows.append({"area": area, "files": modules, **c})
    rest = {"passed": 0, "failed": 0, "skipped": 0}
    for m, entry in counts.items():
        if m not in claimed:
            for k in rest:
                rest[k] += entry[k]
    rows.append({"area": "Other (UI layout, entry points, tooling)", "files": ["(remaining)"], **rest})
    total = {k: sum(r[k] for r in rows) for k in ("passed", "failed", "skipped")}
    return {"rows": rows, "total": total, "duration_s": round(duration, 1),
            "pytest_exit_code": proc.returncode}


# =============================================================================
# the local evaluation server and its clients
# =============================================================================

class Session:
    """One real client connection (real TLS, real login) with timestamped events."""

    def __init__(self, harness, name, peer):
        self.harness, self.name, self.peer = harness, name, peer
        self.events = []  # (perf_counter, kind, data)
        self.timing = {}
        t0 = time.perf_counter()
        sock = connect_tls(HOST, harness.port, on_cert_fingerprint=lambda fp: None)
        self.timing["tls_connect_ms"] = (time.perf_counter() - t0) * 1000
        self.sock = sock
        self.client = SecureChatClient(
            sock, username=name, peer=peer,
            event_callback=lambda kind, data: self.events.append((time.perf_counter(), kind, data)))
        threading.Thread(target=self.client.receive_loop, daemon=True).start()
        t1 = time.perf_counter()
        self.client.login(name, PASSWORD)
        result = self.client.auth_results.get(timeout=60)
        self.timing["login_ms"] = (time.perf_counter() - t1) * 1000
        if not result or not result.get("success"):
            raise RuntimeError(f"login failed for {name}: {result}")
        self.client.rsa_private_key = harness.keys[name]
        self.client.lab_mode = bool(result.get("lab_mode"))

    def fetch_peer_key(self):
        t = time.perf_counter()
        ok = self.client.fetch_peer_public_key(timeout=30)
        self.timing["fetch_peer_key_ms"] = (time.perf_counter() - t) * 1000
        return ok

    def wait(self, predicate, timeout=15.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.001)
        return predicate()

    def has_event(self, kind, **match):
        return any(k == kind and all(d.get(x) == y for x, y in match.items())
                   for _t, k, d in self.events)

    def displayed(self, text):
        return any(t["message"] == text for t in self.client.transcript)

    def close(self):
        self.client.stop_event.set()
        try:
            self.sock.shutdown(2)
        except OSError:
            pass
        self.sock.close()


class Harness:
    """An in-process, lab-mode relay with a temporary user store, security log
    and exports folder, on an OS-chosen port."""

    def __init__(self, tmp, backoff_seconds=0.5):
        self.tmp = tmp
        self.keys = {}
        self.exports_dir = os.path.join(tmp, "exports")
        self.log_path = os.path.join(tmp, "security_events.jsonl")
        store = os.path.join(tmp, "users.json")
        self._saved = {n: getattr(server_module, n)
                       for n in ("register_user", "verify_user", "get_public_key", "log_event")}
        for name in ("register_user", "verify_user", "get_public_key"):
            setattr(server_module, name, functools.partial(self._saved[name], path=store))
        server_module.log_event = lambda event, **fields: real_log_event(
            event, path=self.log_path, **fields)
        # Production lockout defaults (5 failures / 5 minutes) except: the lock
        # lasts `backoff_seconds` so a burst can be repeated quickly, and the
        # per-address rate limit is off (it would otherwise throttle the
        # hundreds of logins this experiment makes from one address).
        self.lockout = LockoutGuard(threshold=5, window=300, backoff_schedule=(backoff_seconds,),
                                    addr_limit=10 ** 9)
        self.backoff = backoff_seconds
        self.server = server_module.ChatServer(HOST, 0, lab_mode=True, lockout=self.lockout)
        self.port = self.server.listen()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=10)
        for name, fn in self._saved.items():
            setattr(server_module, name, fn)

    def register(self, name):
        priv, pub = generate_rsa_keypair()
        sock = connect_tls(HOST, self.port, on_cert_fingerprint=lambda fp: None)
        c = SecureChatClient(sock, username=name, peer="x")
        threading.Thread(target=c.receive_loop, daemon=True).start()
        c.register(name, PASSWORD, public_key_pem=serialize_public_key(pub).decode("ascii"))
        result = c.auth_results.get(timeout=60)
        if not result or not result.get("success"):
            raise RuntimeError(f"registration failed for {name}: {result}")
        c.stop_event.set()
        sock.close()
        self.keys[name] = priv
        self.wait_offline([name])

    def wait_offline(self, names, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.server._lock:
                if not any(n in self.server.clients for n in names):
                    return
            time.sleep(0.005)
        raise RuntimeError(f"server never dropped {names}")

    def pair(self, a="eval_alice", b="eval_bob"):
        """Two logged-in clients with an established signed session. (alice <
        bob alphabetically, so alice is the one that initiates the handshake.)"""
        sa, sb = Session(self, a, b), Session(self, b, a)
        sa.fetch_peer_key()
        sb.fetch_peer_key()
        if not sa.wait(lambda: sa.client.session_key is not None and sb.client.session_key is not None,
                       timeout=30):
            raise RuntimeError("session was never established")
        return sa, sb

    def close_sessions(self, *sessions):
        for s in sessions:
            s.close()
        self.wait_offline([s.name for s in sessions])

    def login_attempt(self, name, password):
        """One login over a fresh TLS connection; returns (reply, elapsed_ms)."""
        t = time.perf_counter()
        sock = connect_tls(HOST, self.port, on_cert_fingerprint=lambda fp: None)
        c = SecureChatClient(sock, username=None, peer="x")
        threading.Thread(target=c.receive_loop, daemon=True).start()
        c.login(name, password)
        reply = c.auth_results.get(timeout=60) or {}
        elapsed = (time.perf_counter() - t) * 1000
        c.stop_event.set()
        sock.close()
        return reply, elapsed

    def count_events(self, event_type):
        return sum(1 for e in read_events(self.log_path) if e["event"] == event_type)


# =============================================================================
# 2. attack resistance
# =============================================================================

def trial_tamper(h, i):
    a, b = h.pair()
    text = f"tamper-{i}"
    a.client.send_envelope({"type": "lab_control", "action": "tamper_next"})
    a.client.send_message(text)
    caught = b.wait(lambda: b.has_event("message_rejected", reason="decryption_failed"))
    result = {"detected": caught and not b.displayed(text),
              "check": "AES-GCM authentication tag" if caught else None}
    h.close_sessions(a, b)
    return result


def trial_replay(h, i):
    a, b = h.pair()
    text = f"replay-{i}"
    a.client.send_message(text)
    b.wait(lambda: b.displayed(text))
    a.client.send_envelope({"type": "lab_control", "action": "replay_last"})
    caught = b.wait(lambda: b.has_event("message_rejected", reason="replay_duplicate"))
    shown_once = sum(1 for t in b.client.transcript if t["message"] == text) == 1
    result = {"detected": caught and shown_once,
              "check": "duplicate nonce (replay) check" if caught else None}
    h.close_sessions(a, b)
    return result


def trial_drop(h, i):
    a, b = h.pair()
    dropped, follow = f"dropped-{i}", f"follow-{i}"
    a.client.send_envelope({"type": "lab_control", "action": "drop_next"})
    a.client.send_message(dropped)
    a.client.send_message(follow)
    caught = b.wait(lambda: b.has_event("chain_warning", reason="chain_gap"))
    b.wait(lambda: b.displayed(follow))
    result = {"detected": caught and not b.displayed(dropped),
              "check": "hash-chain sequence gap" if caught else None}
    h.close_sessions(a, b)
    return result


def trial_mitm(h, i):
    a = Session(h, "eval_alice", "eval_bob")          # alice joins first and arms the attack
    a.fetch_peer_key()
    a.client.send_envelope({"type": "lab_control", "action": "mitm_next_handshake"})
    armed = a.wait(lambda: a.has_event("lab_control_result", armed=True))
    b = Session(h, "eval_bob", "eval_alice")         # bob joins; alice initiates; relay swaps the key
    b.fetch_peer_key()
    caught = armed and b.wait(lambda: b.has_event("handshake_aborted"))
    result = {"detected": bool(caught) and b.client.session_key is None,
              "check": "RSA signature on the ECDH handshake" if caught else None}
    h.close_sessions(a, b)
    return result


def make_base_evidence(h):
    a, b = h.pair()
    for i in range(3):
        a.client.send_message(f"base message from alice {i}")
        b.wait(lambda n=i: b.displayed(f"base message from alice {n}"))
        b.client.send_message(f"base reply from bob {i}")
        a.wait(lambda n=i: a.displayed(f"base reply from bob {n}"))
    path = a.client.export_evidence(h.exports_dir)
    with open(path, encoding="utf-8") as f:
        evidence = json.load(f)
    h.close_sessions(a, b)
    return evidence


def tamper_evidence(evidence, style, rng):
    import copy
    data = copy.deepcopy(evidence)
    records = data["records"]
    if style == 0:   # change one word of one message
        r = records[rng.randrange(len(records))]
        words = r["message"].split(" ")
        words[rng.randrange(len(words))] = "EDITED"
        r["message"] = " ".join(words)
        return data, "edit one word"
    if style == 1:   # delete a record
        del records[rng.randrange(len(records))]
        return data, "delete a record"
    if style == 2:   # reorder two records from the same sender
        by_sender = {}
        for idx, r in enumerate(records):
            by_sender.setdefault(r["sender"], []).append(idx)
        group = next(v for v in by_sender.values() if len(v) >= 2)
        i, j = rng.sample(group, 2)
        records[i], records[j] = records[j], records[i]
        return data, "reorder two records"
    data["session"]["started_at"] += 3600       # edit metadata
    return data, "edit metadata"


def run_attacks(h, n_attacks, say_progress):
    results = {}
    trials = [("Message tampering", trial_tamper, "tamper"),
              ("Message replay", trial_replay, "replay"),
              ("Message drop (relay deletes)", trial_drop, "drop"),
              ("MITM handshake key swap", trial_mitm, "mitm")]
    for label, fn, key in trials:
        say_progress(f"  attack: {label} x{n_attacks}")
        t0 = time.time()
        outcomes = []
        for i in range(n_attacks):
            try:
                outcomes.append(fn(h, i))
            except Exception as exc:  # a trial that errors is counted as NOT detected
                outcomes.append({"detected": False, "check": None, "error": repr(exc)})
        results[key] = {"label": label, "outcomes": outcomes, "seconds": round(time.time() - t0, 1)}

    say_progress(f"  attack: edited evidence file x{n_attacks}")
    base = make_base_evidence(h)
    rng = random.Random(1234)
    clean = [verify_transcript.verify_evidence(base).valid for _ in range(n_attacks)]
    outcomes = []
    for i in range(n_attacks):
        data, how = tamper_evidence(base, i % 4, rng)
        report = verify_transcript.verify_evidence(data)
        outcomes.append({"detected": not report.valid, "how": how,
                         "check": ("verifier: " + report.failures[0][1]) if report.failures else None})
    results["evidence"] = {"label": "Edited evidence file", "outcomes": outcomes,
                           "clean_verifications": len(clean), "clean_false_invalid": clean.count(False)}

    say_progress(f"  attack: wrong-password bursts x{n_attacks}")
    h.register("eval_target")
    outcomes, wrong_ms, locked_ms, legit_ok = [], [], [], 0
    for i in range(n_attacks):
        before = h.count_events("account_locked")
        replies = []
        for k in range(5):
            reply, ms = h.login_attempt("eval_target", f"wrong-{i}-{k}")
            replies.append(reply)
            wrong_ms.append(ms)
        sixth, ms6 = h.login_attempt("eval_target", f"wrong-{i}-6")
        locked_ms.append(ms6)
        generic = all(not r.get("success") and r.get("reason") == "invalid username or password"
                      for r in replies)
        locked = "locked" in (sixth.get("reason") or "")
        detected = generic and locked and h.count_events("account_locked") == before + 1
        outcomes.append({"detected": detected, "check": "account lockout after 5 failures"
                         if detected else None})
        time.sleep(h.backoff + 0.3)                      # let the lock expire
        legit_ok += bool(h.login_attempt("eval_target", PASSWORD)[0].get("success"))
    results["burst"] = {"label": "Wrong-password burst (5 + 1)", "outcomes": outcomes,
                        "legit_login_after_expiry_ok": legit_ok,
                        "wrong_attempt_ms": summarize(wrong_ms), "locked_attempt_ms": summarize(locked_ms)}
    return results


def run_normal_traffic(h, sessions, per_session, say_progress):
    say_progress(f"  normal traffic: {sessions} sessions x {per_session} messages")
    total = delivered = undelivered = false_events = 0
    kinds = {}
    for s in range(sessions):
        a, b = h.pair()
        for m in range(per_session):
            sender, receiver = (a, b) if m % 2 == 0 else (b, a)
            text = f"normal-{s}-{m}-the quick brown fox"
            sender.client.send_message(text)
            total += 1
            if receiver.wait(lambda t=text: receiver.displayed(t), timeout=10):
                delivered += 1
            else:
                undelivered += 1
        time.sleep(0.05)
        for side in (a, b):
            for _t, kind, data in side.events:
                if kind in ("message_rejected", "chain_warning", "handshake_aborted"):
                    false_events += 1
                    key = data.get("reason") or kind
                    kinds[key] = kinds.get(key, 0) + 1
        h.close_sessions(a, b)
    return {"sessions": sessions, "messages_per_session": per_session, "messages": total,
            "delivered": delivered, "undelivered": undelivered,
            "false_rejection_events": false_events, "false_rejection_kinds": kinds,
            "false_rejections": undelivered + false_events}


# =============================================================================
# 3. performance
# =============================================================================

def bench(fn, n, warmup=5):
    for _ in range(warmup):
        fn()
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return times


def run_performance(h, params, say_progress):
    perf = {}
    message = b"Patient 4471: please prepare amoxicillin 500 mg, three times daily for 7 days."
    n = params["iterations"]

    say_progress(f"  crypto primitives x{n}")
    key = generate_key()
    box = encrypt(key, message)
    perf["AES-256-GCM encrypt (chat message)"] = bench(lambda: encrypt(key, message), n)
    perf["AES-256-GCM decrypt (chat message)"] = bench(
        lambda: decrypt(key, box["nonce"], box["ciphertext"], box["tag"]), n)
    priv, pub = generate_rsa_keypair()
    record = message + b" " * 100                         # about the size of a signed chat record
    sig = sign(priv, record)
    perf["RSA-2048 sign (chat record)"] = bench(lambda: sign(priv, record), n)
    perf["RSA-2048 verify (chat record)"] = bench(lambda: verify(pub, record, sig), n)

    def x25519_exchange():
        a_priv, a_pub = generate_ecdh_keypair()
        b_priv, b_pub = generate_ecdh_keypair()
        compute_shared_key(a_priv, b_pub)
        compute_shared_key(b_priv, a_pub)
    perf["X25519 key exchange + HKDF (both sides)"] = bench(x25519_exchange, n)

    say_progress(f"  PBKDF2 x{params['pbkdf2_n']} ({MIN_ITERATIONS:,} iterations)")
    stored = hash_password(PASSWORD)
    perf[f"PBKDF2-HMAC-SHA256 hash ({MIN_ITERATIONS:,} iter.)"] = bench(
        lambda: hash_password(PASSWORD), params["pbkdf2_n"], warmup=1)
    perf[f"PBKDF2-HMAC-SHA256 verify ({MIN_ITERATIONS:,} iter.)"] = bench(
        lambda: verify_password(PASSWORD, stored), params["pbkdf2_n"], warmup=1)
    perf["RSA-2048 key generation (registration only)"] = bench(
        generate_rsa_keypair, params["keygen_n"], warmup=1)

    say_progress(f"  end-to-end message latency x{params['e2e_n']} through the real TLS server")
    a, b = h.pair()
    latencies = []
    for i in range(params["e2e_n"] + 5):
        sender, receiver = (a, b) if i % 2 == 0 else (b, a)
        text = f"latency-{i}-{message.decode()}"
        start = len(receiver.events)
        t0 = time.perf_counter()
        sender.client.send_message(text)
        deadline = time.time() + 15
        while time.time() < deadline:
            hit = next((t for t, k, d in receiver.events[start:]
                        if k == "message_received" and d.get("message") == text), None)
            if hit is not None:
                if i >= 5:                               # first 5 are warm-up
                    latencies.append((hit - t0) * 1000)
                break
            time.sleep(0.0002)
        else:
            raise RuntimeError("message never arrived during the latency test")
    h.close_sessions(a, b)
    perf["End-to-end message latency (send -> received and verified)"] = latencies

    say_progress(f"  full session setup x{params['setup_n']} (TLS connect + login + signed handshake)")
    totals, tls_c, logins, rest = [], [], [], []
    for _ in range(params["setup_n"]):
        t0 = time.perf_counter()
        sa = Session(h, "eval_alice", "eval_bob")
        sb = Session(h, "eval_bob", "eval_alice")
        sa.fetch_peer_key()
        sb.fetch_peer_key()
        sa.wait(lambda: sa.client.session_key is not None and sb.client.session_key is not None, 30)
        total = (time.perf_counter() - t0) * 1000
        totals.append(total)
        parts = [sa.timing["tls_connect_ms"], sb.timing["tls_connect_ms"],
                 sa.timing["login_ms"], sb.timing["login_ms"]]
        tls_c += parts[:2]
        logins += parts[2:]
        rest.append(total - sum(parts))
        h.close_sessions(sa, sb)
    perf["Full session setup, two users (connect + login + handshake)"] = totals
    perf["  of which: one TLS 1.3 connect"] = tls_c
    perf["  of which: one login (incl. PBKDF2 verify)"] = logins
    perf["  of which: peer-key fetch + signed ECDH handshake"] = rest
    return perf


# =============================================================================
# reporting
# =============================================================================

def build_summary(results):
    """Return (functional_rows, attack_rows, normal_rows, perf_rows, headline) as tables."""
    f = results["functional"]
    functional = [[r["area"], ", ".join(r["files"]), r["passed"], r["failed"], r["passed"] + r["failed"]]
                  for r in f["rows"]]
    functional.append(["TOTAL", "", f["total"]["passed"], f["total"]["failed"],
                       f["total"]["passed"] + f["total"]["failed"]])

    attacks, grand_n, grand_ok = [], 0, 0
    for key in ("tamper", "replay", "drop", "mitm", "evidence", "burst"):
        a = results["attacks"][key]
        outs = a["outcomes"]
        n, ok = len(outs), sum(1 for o in outs if o["detected"])
        grand_n, grand_ok = grand_n + n, grand_ok + ok
        checks = {}
        for o in outs:
            if o["detected"]:
                checks[o["check"]] = checks.get(o["check"], 0) + 1
        attacks.append([a["label"], n, ok, pct(ok, n),
                        "; ".join(f"{c} ({k})" for c, k in sorted(checks.items())) or "-"])
    attacks.append(["ALL ATTACKS", grand_n, grand_ok, pct(grand_ok, grand_n), ""])

    nt = results["normal"]
    normal = [
        ["Normal messages sent", nt["messages"]],
        ["Delivered and displayed intact", nt["delivered"]],
        ["Not delivered", nt["undelivered"]],
        ["Wrongly flagged (rejected / warned / aborted)", nt["false_rejection_events"]],
        ["FALSE-REJECTION RATE", pct(nt["false_rejections"], nt["messages"])],
        ["Clean evidence files verified as INVALID",
         f"{results['attacks']['evidence']['clean_false_invalid']} of "
         f"{results['attacks']['evidence']['clean_verifications']}"],
        ["Legitimate logins refused after a lock expired",
         f"{results['attacks']['burst']['wrong_attempt_ms'] and (len(results['attacks']['burst']['outcomes']) - results['attacks']['burst']['legit_login_after_expiry_ok'])}"
         f" of {len(results['attacks']['burst']['outcomes'])}"],
    ]

    perf_rows = []
    for name, values in results["performance"].items():
        s = summarize(values)
        passed = s["p95_ms"] < REQUIREMENT_MS
        perf_rows.append([name, s["n"], fmt_ms(s["median_ms"]), fmt_ms(s["p95_ms"]), fmt_ms(s["max_ms"]),
                          "PASS" if passed else "FAIL"])
    return functional, attacks, normal, perf_rows


def headline(results):
    _f, attacks, normal, perf_rows = build_summary(results)
    total = attacks[-1]
    e2e = next(r for r in perf_rows if r[0].startswith("End-to-end"))
    setup = next(r for r in perf_rows if r[0].startswith("Full session setup"))
    return {
        "tests": f"{results['functional']['total']['passed']}/"
                 f"{results['functional']['total']['passed'] + results['functional']['total']['failed']}",
        "attacks": f"{total[2]}/{total[1]} ({total[3]})",
        "false_rejection": next(r[1] for r in normal if r[0] == "FALSE-REJECTION RATE"),
        "e2e_median_ms": e2e[2], "e2e_p95_ms": e2e[3],
        "setup_median_ms": setup[2], "setup_p95_ms": setup[3],
        "all_pass": all(r[-1] == "PASS" for r in perf_rows),
    }


def print_summary(results):
    functional, attacks, normal, perf_rows = build_summary(results)
    m, p = results["machine"], results["parameters"]
    say("=" * 100)
    say("SECURITY AND PERFORMANCE EVALUATION")
    say(f"{m['cpu']} | {m['os'].split(' (')[0]} | Python {m['python']} | {results['when']}")
    say("=" * 100)
    say("\n1. FUNCTIONAL VERIFICATION (pytest)")
    say(text_table(["Area", "Passed", "Failed"], [[r[0], r[2], r[3]] for r in functional]))
    say("\n2. ATTACK RESISTANCE (each attack run N times through the real lab-mode relay)")
    say(text_table(["Attack", "Tried", "Detected", "Rate", "Detected by"], attacks))
    say("\n   Normal traffic")
    say(text_table(["Measure", "Result"], normal))
    say(f"\n3. PERFORMANCE OVERHEAD (requirement: p95 < {REQUIREMENT_MS / 1000:.0f} s = {REQUIREMENT_MS:.0f} ms)")
    say(text_table(["Operation", "N", "Median ms", "p95 ms", "Max ms", "< 1 s"], perf_rows))
    h = headline(results)
    say("\n" + "-" * 100)
    say(f"Tests {h['tests']} | attacks detected {h['attacks']} | false-rejection rate {h['false_rejection']} | "
        f"message latency median {h['e2e_median_ms']} ms (p95 {h['e2e_p95_ms']} ms) | "
        f"session setup median {h['setup_median_ms']} ms")
    say(f"Real-time requirement (< 1 s): {'PASS' if h['all_pass'] else 'FAIL'}   |   "
        f"real data/ unchanged: {'yes' if results['real_data_unchanged'] else 'NO'}")
    say(f"Parameters: {json.dumps(p)}")


def write_markdown(results, path, command):
    functional, attacks, normal, perf_rows = build_summary(results)
    m, p, h = results["machine"], results["parameters"], headline(results)
    b = results["attacks"]["burst"]
    lines = [
        "# Security and performance evaluation (measured)",
        "",
        "Generated by `tools/evaluate_security.py`. Evaluation only: no protocol or crypto behaviour is changed;",
        "every number below comes from driving the real code.",
        "",
        f"Run on {results['when']}.  Reproduce with:",
        "",
        "```",
        command,
        "```",
        "",
        "## Headline",
        "",
        f"- Test suite: **{h['tests']}** tests pass.",
        f"- Attacks detected: **{h['attacks']}**; false-rejection rate on normal traffic: **{h['false_rejection']}**.",
        f"- End-to-end message latency (send to received and verified, through the real TLS server): "
        f"median **{h['e2e_median_ms']} ms**, p95 **{h['e2e_p95_ms']} ms**.",
        f"- Full session setup (TLS connect + login + signed handshake, two users): median "
        f"**{h['setup_median_ms']} ms**, p95 **{h['setup_p95_ms']} ms**.",
        f"- Review 1 requirement (encryption overhead < 1 s): **{'PASS' if h['all_pass'] else 'FAIL'}** "
        f"(judged on the 95th percentile of every measurement).",
        "",
        "## Machine and parameters",
        "",
        md_table(["Item", "Value"], [
            ["CPU", f"{m['cpu']} ({m['cores']} logical cores, {m['machine']})"],
            ["OS", m["os"]], ["Python", m["python"]], ["OpenSSL", m["openssl"]],
            ["cryptography / pycryptodome", f"{m['cryptography']} / {m['pycryptodome']}"],
            ["PBKDF2 iterations", f"{m['pbkdf2_iterations']:,}"],
        ]),
        "",
        "Parameters used: `" + json.dumps(p) + "`",
        "",
        "Everything ran against a local lab-mode server on an OS-chosen loopback port with a temporary user store,",
        "security log and exports folder (deleted afterwards).",
        "",
        f"> **Caveat 1 - lockout duration.** For the repeated wrong-password trials the lock duration was shortened to "
        f"**{p['lock_seconds']} s** so a burst could be repeated {p['attacks_per_type']} times quickly. The production "
        "schedule is **30 s, 60 s, 120 s, 300 s, 900 s (capped at 15 min)**. The threshold (5 failures within 5 minutes) "
        "is the production one; the per-address rate limit was disabled so it would not throttle the experiment's own logins.",
        ">",
        "> **Caveat 2 - loopback, one machine.** All timings were taken on loopback on a single machine "
        f"({m['cpu']}), with client and server sharing one CPU. Real network latency would be **added** to the "
        "end-to-end message and session-setup figures; the numbers measure the cryptographic and protocol cost only.",
        "",
        "## 1. Functional verification",
        "",
        f"`pytest tests/` ({results['functional']['duration_s']} s). Grouped by area:",
        "",
        md_table(["Area", "Test files", "Passed", "Failed", "Total"], functional),
        "",
        "## 2. Attack resistance",
        "",
        "Each attack was run through the real lab-mode relay (the same `lab_control` actions the Attack Lab uses), "
        "with a fresh pair of real clients per trial. An attack counts as **detected** only if the receiving side's "
        "own check flagged it **and** the tampered/replayed/dropped content was not displayed. The server never "
        "announces a detection; the table names the client-side check that fired.",
        "",
        md_table(["Attack", "Attempted", "Detected", "Detection rate", "Detected by (check, count)"], attacks),
        "",
        "Normal traffic through the same setup (no attack armed), and false rejections:",
        "",
        md_table(["Measure", "Result"], normal),
        "",
        f"Lockout evidence: median time of a wrong-password attempt {fmt_ms(b['wrong_attempt_ms']['median_ms'])} ms "
        f"(runs PBKDF2) versus {fmt_ms(b['locked_attempt_ms']['median_ms'])} ms for an attempt against a locked "
        "account (PBKDF2 skipped). Both include a fresh TLS connection.",
        "",
        "Evidence-file edits rotate through four styles: change one word, delete a record, reorder two records, "
        "edit metadata.",
        "",
        "## 3. Performance overhead",
        "",
        f"Requirement (Review 1): encryption overhead small enough for real-time chat, **< 1 s**. A row passes if its "
        f"95th percentile is below {REQUIREMENT_MS:.0f} ms. Times in milliseconds.",
        "",
        md_table(["Operation", "N", "Median", "p95", "Max", "< 1 s"], perf_rows),
        "",
        "Notes: the PBKDF2 and RSA key-generation rows are one-off costs (login/registration), deliberately slow. "
        "Latency and setup were measured on loopback, so they exclude real network delay; the cryptographic and "
        "protocol cost is what is being measured.",
        "",
        "## Limitations",
        "",
        "- One machine, loopback only: no real network latency, and the client and server share one CPU.",
        "- 'Detected' is judged by the receiving client's own events and displayed transcript, within a 10-15 s wait.",
        "- The attack counts are small and fixed (see parameters); a 100% rate here shows the checks work on these "
        "attacks, not that no attack could ever evade them.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# =============================================================================
# main
# =============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(description="Security and performance evaluation.")
    parser.add_argument("--quick", action="store_true", help="short run (about a minute)")
    parser.add_argument("--attacks", type=int, help="trials per attack type (default 20, quick 5)")
    parser.add_argument("--normal-sessions", type=int, help="normal sessions (default 10, quick 4)")
    parser.add_argument("--messages-per-session", type=int, help="messages per normal session "
                        "(default 20, quick 10)")
    parser.add_argument("--iterations", type=int, help="iterations per crypto micro-benchmark "
                        "(default 500, quick 50)")
    parser.add_argument("--skip-tests", action="store_true", help="skip the pytest run (functional table)")
    parser.add_argument("--output-dir", default=os.path.join(ROOT, "docs"))
    parser.add_argument("--show", action="store_true", help="print the last saved summary and exit")
    args = parser.parse_args(argv)

    json_path = os.path.join(args.output_dir, "evaluation_results.json")
    if args.show:
        with open(json_path, encoding="utf-8") as f:
            print_summary(json.load(f))
        return 0

    q = args.quick
    params = {
        "quick": q, "attacks_per_type": args.attacks or (5 if q else 20),
        "normal_sessions": args.normal_sessions or (4 if q else 10),
        "messages_per_session": args.messages_per_session or (10 if q else 20),
        "iterations": args.iterations or (50 if q else 500),
        "pbkdf2_n": 5 if q else 30, "keygen_n": 5 if q else 20,
        "e2e_n": 50 if q else 500, "setup_n": 5 if q else 30,
        "lock_seconds": 0.5, "message_bytes": 78,
    }
    command = "python tools/evaluate_security.py" + (" --quick" if q else "")
    for flag, key in (("--attacks", "attacks"), ("--normal-sessions", "normal_sessions"),
                      ("--messages-per-session", "messages_per_session"),
                      ("--iterations", "iterations")):
        if getattr(args, key):
            command += f" {flag} {getattr(args, key)}"

    real_data = os.path.join(ROOT, "data")
    data_before = tree_hash(real_data)
    tmp = tempfile.mkdtemp(prefix="securechat_eval_")
    results = {"when": time.strftime("%Y-%m-%d %H:%M"), "machine": machine_info(), "parameters": params}
    started = time.time()
    harness = None
    try:
        say("== evaluating (temporary data in %s; your real data/ is not used) ==" % tmp)
        if args.skip_tests:
            results["functional"] = {"rows": [{"area": a, "files": f, "passed": 0, "failed": 0, "skipped": 0}
                                              for a, f in AREAS], "total": {"passed": 0, "failed": 0,
                                                                          "skipped": 0},
                                     "duration_s": 0, "pytest_exit_code": None}
        else:
            say("[1/4] functional verification: running the pytest suite")
            results["functional"] = run_functional(tmp)
        with silenced():
            harness = Harness(tmp, backoff_seconds=params["lock_seconds"])
            for name in ("eval_alice", "eval_bob"):
                harness.register(name)
            say("[2/4] attack resistance")
            results["attacks"] = run_attacks(harness, params["attacks_per_type"], say)
            results["normal"] = run_normal_traffic(harness, params["normal_sessions"],
                                                    params["messages_per_session"], say)
            say("[3/4] performance overhead")
            results["performance"] = {k: [round(x, 4) for x in v] for k, v in
                                      run_performance(harness, params, say).items()}
    finally:
        if harness is not None:
            with silenced():
                harness.close()
        shutil.rmtree(tmp, ignore_errors=True)
    results["real_data_unchanged"] = tree_hash(real_data) == data_before
    results["runtime_s"] = round(time.time() - started, 1)

    say("[4/4] writing reports")
    os.makedirs(args.output_dir, exist_ok=True)
    write_markdown(results, os.path.join(args.output_dir, "evaluation_results.md"), command)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    say("")
    print_summary(results)
    say(f"\nWrote {os.path.relpath(os.path.join(args.output_dir, 'evaluation_results.md'), ROOT)} and "
        f"evaluation_results.json  (runtime {results['runtime_s']} s)")
    return 0 if results["real_data_unchanged"] else 1


if __name__ == "__main__":
    sys.exit(main())
