"""Pure-function tests for scoring. No model load required."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scoring import (  # noqa: E402
    extract_registrable,
    levenshtein,
    structural_score,
    tld_of,
    tokens_of,
)


# --- extract_registrable --------------------------------------------------

def test_extract_simple():
    assert extract_registrable("hdfc.com") == "hdfc"


def test_extract_compound_tld():
    assert extract_registrable("login.icici.co.in") == "login.icici"


def test_extract_wildcard_prefix():
    assert extract_registrable("*.icici.com") == "icici"


def test_extract_lowercase():
    assert extract_registrable("ICICI.COM") == "icici"


# --- tokens_of ------------------------------------------------------------

def test_tokens_split_on_dash_and_dot():
    assert tokens_of("icici-online.login") == ["icici", "online", "login"]


# --- tld_of ---------------------------------------------------------------

def test_tld_simple():
    assert tld_of("hdfc.com") == "com"


def test_tld_compound_returns_effective():
    assert tld_of("hdfc.co.in") == "co"


# --- Levenshtein ----------------------------------------------------------

def test_lev_identity():
    assert levenshtein("abc", "abc", 2) == 0


def test_lev_one_edit():
    assert levenshtein("hdfc", "hdfg", 2) == 1


def test_lev_two_edits():
    assert levenshtein("icici", "ic1c1", 2) == 2


def test_lev_early_exit():
    # Length difference > max, returns max+1 immediately.
    assert levenshtein("a", "abcdef", 2) == 3


def test_lev_above_cap():
    # Not close at all.
    assert levenshtein("sbi", "zerodhabank", 2) == 3


# --- structural_score -----------------------------------------------------

def test_structural_benign_domain_low_score():
    score, feats = structural_score("google.com", not_before=time.time() - 365 * 86400)
    assert score < 0.3
    assert feats["hyphen_count"] == 0


def test_structural_phishy_domain_passes_threshold():
    # Deep subdomain, hyphens, risky TLD, punycode, fresh cert.
    score, feats = structural_score(
        "secure-login-icici.verify.xn--80ak6aa92e.xyz", not_before=time.time()
    )
    assert score >= 0.6
    assert feats["risky_tld"] == 1.0
    assert feats["punycode"] == 1.0


def test_structural_fresh_cert_boosts():
    high, _ = structural_score("icici-login-verify.com", not_before=time.time())
    low, _ = structural_score("icici-login-verify.com", not_before=time.time() - 30 * 86400)
    assert high >= low


def test_structural_none_not_before_ok():
    score, feats = structural_score("hdfc.com", not_before=None)
    assert 0.0 <= score <= 1.0
    assert feats["cert_age_days"] == 0.0


def test_structural_feature_names_match_dict():
    _, feats = structural_score("example.com", not_before=0)
    from scoring import STRUCTURAL_FEATURE_NAMES

    assert set(feats.keys()) == set(STRUCTURAL_FEATURE_NAMES)
