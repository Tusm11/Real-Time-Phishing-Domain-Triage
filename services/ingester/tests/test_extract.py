"""Unit tests for extract_record. No network, no redis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import extract_record  # noqa: E402


def _msg(domains, cn="example.com", issuer="Let's Encrypt", not_before=1_700_000_000):
    return {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": domains,
                "subject": {"CN": cn},
                "issuer": {"O": issuer},
                "not_before": not_before,
            },
            "seen": 1_700_000_100,
            "source": {"name": "ct/log"},
        },
    }


def test_extract_happy_path():
    r = extract_record(_msg(["a.example.com", "example.com"]))
    assert r is not None
    assert r["domains"] == ["a.example.com", "example.com"]
    assert r["cn"] == "example.com"
    assert r["issuer"] == "Let's Encrypt"
    assert r["not_before"] == 1_700_000_000
    assert r["seen_at"] == 1_700_000_100


def test_extract_heartbeat_returns_none():
    assert extract_record({"message_type": "heartbeat"}) is None


def test_extract_empty_domains_returns_none():
    assert extract_record(_msg([])) is None


def test_extract_missing_leaf_cert():
    assert extract_record({"message_type": "certificate_update", "data": {}}) is None


def test_extract_handles_missing_fields():
    msg = {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": ["x.com"]}, "seen": 0},
    }
    r = extract_record(msg)
    assert r is not None
    assert r["cn"] == ""
    assert r["issuer"] == ""
    assert r["not_before"] is None
