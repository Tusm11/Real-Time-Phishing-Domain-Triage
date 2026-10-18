"""Tests for the stage functions in main (A and B only — C needs the model)."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import stage_a, stage_b  # noqa: E402

BRANDS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "zerodha", "groww"]


def test_stage_a_exact_substring():
    r = stage_a("icici-login.xyz", BRANDS)
    assert r.passed
    assert r.matched_brand == "icici"


def test_stage_a_levenshtein_match():
    r = stage_a("hdfg-secure.com", BRANDS)
    assert r.passed
    assert r.matched_brand == "hdfc"
    assert r.distance == 1


def test_stage_a_no_match():
    r = stage_a("completely-unrelated.io", BRANDS)
    assert not r.passed


def test_stage_a_compound_tld_still_matches():
    r = stage_a("login.icici.co.in", BRANDS)
    assert r.passed
    assert r.matched_brand == "icici"


def test_stage_b_benign_fails_threshold():
    r = stage_b("google.com", not_before=time.time() - 365 * 86400)
    assert not r.passed
    assert r.score < 0.6


def test_stage_b_phishy_passes():
    # Multiple strong signals: deep subdomain, hyphens, punycode label,
    # risky TLD, fresh cert — the kind of domain Stage B exists to catch.
    r = stage_b(
        "secure-login-verify.icici-support.online.xn--80ak6aa92e.xyz",
        not_before=time.time(),
    )
    assert r.passed
    assert r.score >= 0.6


def test_stage_b_mildly_phishy_below_threshold():
    # Correctly rejected — only a couple of weak signals, needs LLM/C-stage
    # for actual judgment. Documents calibration intent.
    r = stage_b("secure-login-verify.icici-support.xyz", not_before=time.time())
    assert not r.passed
    assert 0.3 <= r.score < 0.6
