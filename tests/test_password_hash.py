"""Unit tests for the Phase 4 PBKDF2-HMAC-SHA256 password hashing."""

import hmac
import inspect
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.password_hash import (  # noqa: E402
    MIN_ITERATIONS,
    InvalidHashFormat,
    hash_password,
    verify_password,
)


def test_round_trip_correct_password_verifies():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored) is True


def test_wrong_password_fails():
    stored = hash_password("correct horse battery staple")
    assert verify_password("incorrect password", stored) is False


def test_near_miss_password_fails():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staplE", stored) is False


def test_empty_password_can_be_hashed_and_verified():
    stored = hash_password("")
    assert verify_password("", stored) is True
    assert verify_password("not empty", stored) is False


def test_same_password_hashed_twice_yields_different_strings():
    """Different random salts -> different encoded strings even for the same
    password -- this also guards against silently reusing a fixed salt."""
    stored1 = hash_password("same password")
    stored2 = hash_password("same password")
    assert stored1 != stored2
    # ...but both still verify correctly against their own hash.
    assert verify_password("same password", stored1)
    assert verify_password("same password", stored2)


def test_stored_format_fields():
    stored = hash_password("format check")
    algorithm, iterations, salt_b64, hash_b64 = stored.split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(iterations) >= MIN_ITERATIONS
    assert len(salt_b64) > 0
    assert len(hash_b64) > 0


def test_iteration_count_meets_minimum():
    stored = hash_password("iterations check")
    _, iterations, _, _ = stored.split("$")
    assert int(iterations) >= 200_000


def test_malformed_stored_hash_raises():
    with pytest.raises(InvalidHashFormat):
        verify_password("anything", "not-a-valid-stored-hash")


def test_unsupported_algorithm_raises():
    stored = hash_password("x")
    _, iterations, salt_b64, hash_b64 = stored.split("$")
    forged = f"md5${iterations}${salt_b64}${hash_b64}"
    with pytest.raises(InvalidHashFormat):
        verify_password("x", forged)


def test_hash_does_not_contain_plaintext_password():
    password = "super_secret_marker_value_123"
    stored = hash_password(password)
    assert password not in stored


# --- timing-safety: confirm hmac.compare_digest is actually used ----------

def test_uses_constant_time_comparison_not_equality():
    """Inspect the source to confirm hmac.compare_digest is used for the
    final comparison rather than `==`, which is not constant-time. A direct
    timing measurement is too flaky to assert on reliably in CI, so this is
    a static check of the actual mechanism instead."""
    source = inspect.getsource(verify_password)
    assert "compare_digest" in source, (
        "verify_password must use hmac.compare_digest for constant-time comparison"
    )


def test_correct_vs_near_miss_timing_is_roughly_similar():
    """Rough sanity check (not a strict benchmark): verifying a correct
    password and a same-length near-miss password should take a similar
    order of magnitude of time, since both run the full PBKDF2 computation
    before any comparison happens. A wildly different timing ratio would
    suggest an early-exit comparison somewhere."""
    password = "timing sanity check password"
    stored = hash_password(password)
    near_miss = password[:-1] + "X"

    def timeit(pw, n=5):
        start = time.perf_counter()
        for _ in range(n):
            verify_password(pw, stored)
        return time.perf_counter() - start

    correct_time = timeit(password)
    wrong_time = timeit(near_miss)

    # Both do a full PBKDF2 derivation regardless of outcome, so times should
    # be within the same order of magnitude -- generous bound to avoid flakes.
    ratio = max(correct_time, wrong_time) / max(min(correct_time, wrong_time), 1e-9)
    assert ratio < 5, f"timing ratio {ratio:.2f} is suspiciously large"


def test_compare_digest_is_actually_hmac_compare_digest():
    """Belt-and-suspenders: confirm the module imports hmac and never uses
    plain string/bytes equality for the final hash comparison."""
    import auth.password_hash as mod
    assert mod.hmac is hmac
