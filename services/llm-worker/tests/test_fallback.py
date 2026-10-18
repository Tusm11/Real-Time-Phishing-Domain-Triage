"""Fallback classifier tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fallback import rule_based_verdict  # noqa: E402


def _cand(a=999, b=0.0, c=0.0, risky=0.0, puny=0.0):
    return {
        "filter_scores": {"a": a, "b": b, "c": c},
        "features": {"risky_tld": risky, "punycode": puny},
    }


def test_zero_votes_benign():
    v, conf, _ = rule_based_verdict(_cand())
    assert v == "benign"
    assert conf <= 0.5


def test_one_vote_suspicious():
    v, _, _ = rule_based_verdict(_cand(a=1))
    assert v == "suspicious"


def test_three_votes_phishing():
    v, conf, _ = rule_based_verdict(_cand(a=1, b=0.8, c=0.9))
    assert v == "phishing"
    assert conf <= 0.7  # fallback confidence is capped


def test_risky_tld_counts():
    v, _, _ = rule_based_verdict(_cand(a=1, b=0.8, risky=1.0))
    assert v == "phishing"
