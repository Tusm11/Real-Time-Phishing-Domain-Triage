"""
Pure functions used by the filter stages. No I/O, no globals.
Kept separate from main.py so the scoring logic is unit-testable in
isolation and can be swapped without touching the pipeline.
"""

from __future__ import annotations

import re
import time
from typing import Iterable

# --- Known registrable TLDs we care about -----------------------------------
# Public Suffix List is overkill for stage B features. We just need to strip
# obvious compound TLDs so "login.icici.co.in" -> "icici".
_COMPOUND_TLDS = frozenset(
    [
        "co.in", "co.uk", "com.au", "com.br", "co.jp", "co.kr", "co.za",
        "ac.in", "ac.uk", "gov.in", "net.in", "org.in", "com.sg",
    ]
)

# Risky TLDs - cheap and heavily abused for phishing.
_RISKY_TLDS = frozenset(
    [
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "monster", "click",
        "zip", "mov", "fit", "work", "country", "support", "live", "rest",
        "quest", "icu", "cfd",
    ]
)

STRUCTURAL_FEATURE_NAMES = [
    "subdomain_depth",
    "hyphen_count",
    "digit_ratio",
    "length",
    "risky_tld",
    "punycode",
    "cert_age_days",
]


# ---------------------------------------------------------------------------
# Domain parsing
# ---------------------------------------------------------------------------

def _strip_known_tld(parts: list[str]) -> list[str]:
    """Remove trailing compound TLD if present, else single TLD. Return the
    remaining labels (what we treat as 'the name')."""
    if len(parts) >= 2:
        tail2 = ".".join(parts[-2:])
        if tail2 in _COMPOUND_TLDS:
            return parts[:-2]
    if len(parts) >= 1:
        return parts[:-1]
    return parts


def extract_registrable(domain: str) -> str:
    """Return the 'name' part of a domain, lowercased, without TLD.

    "login.icici.co.in"  -> "login.icici"
    "icici-online.xyz"   -> "icici-online"
    "www.hdfc.com"       -> "www.hdfc"
    """
    d = domain.lower().strip(".").lstrip("*.")
    if not d:
        return ""
    labels = d.split(".")
    body = _strip_known_tld(labels)
    return ".".join(body)


def tld_of(domain: str) -> str:
    d = domain.lower().strip(".")
    if "." not in d:
        return ""
    labels = d.split(".")
    if len(labels) >= 2 and ".".join(labels[-2:]) in _COMPOUND_TLDS:
        return labels[-2]  # effective TLD for riskiness check
    return labels[-1]


def tokens_of(name: str) -> list[str]:
    """Split a name on '.' and '-' and drop empties. Lowercased."""
    return [t for t in re.split(r"[.\-]+", name.lower()) if t]


# ---------------------------------------------------------------------------
# Levenshtein with early-exit cap
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str, max_distance: int) -> int:
    """Classic DP with an early-exit bound.

    Returns distance up to max_distance+1 (i.e. anything above max is
    reported as max+1 — callers only care about <= max).
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_distance:
        return max_distance + 1
    if la == 0:
        return lb
    if lb == 0:
        return la

    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        row_min = curr[0]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,       # insertion
                prev[j] + 1,           # deletion
                prev[j - 1] + cost,    # substitution
            )
            if curr[j] < row_min:
                row_min = curr[j]
        if row_min > max_distance:
            return max_distance + 1
        prev = curr
    return prev[lb]


# ---------------------------------------------------------------------------
# Structural score (Stage B)
# ---------------------------------------------------------------------------

def _subdomain_depth(domain: str) -> int:
    reg = extract_registrable(domain)
    return reg.count(".")


def _hyphen_count(domain: str) -> int:
    return domain.count("-")


def _digit_ratio(domain: str) -> float:
    name = extract_registrable(domain)
    if not name:
        return 0.0
    digits = sum(1 for c in name if c.isdigit())
    letters = sum(1 for c in name if c.isalpha() or c.isdigit())
    return digits / letters if letters else 0.0


def _is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def _is_risky_tld(domain: str) -> bool:
    return tld_of(domain) in _RISKY_TLDS


def _cert_age_days(not_before: int | float | None, now: float | None = None) -> float:
    if not_before is None:
        return 0.0
    try:
        nb = float(not_before)
    except (TypeError, ValueError):
        return 0.0
    now_ts = time.time() if now is None else now
    return max(0.0, (now_ts - nb) / 86400.0)


def structural_score(
    domain: str, not_before: int | float | None = None
) -> tuple[float, dict[str, float]]:
    """Hand-tuned weighted sum of structural features, normalized to [0, 1].

    This is deliberately interpretable: each feature contributes a bounded
    amount, so you can read the breakdown and understand *why* a domain
    was flagged. Tune the weights by sampling cert streams and labeling.
    """
    subdomain_depth = _subdomain_depth(domain)
    hyphens = _hyphen_count(domain)
    digit_ratio = _digit_ratio(domain)
    length = len(domain)
    risky_tld = 1.0 if _is_risky_tld(domain) else 0.0
    puny = 1.0 if _is_punycode(domain) else 0.0
    age_days = _cert_age_days(not_before)

    # Contributions (each capped). Weights chosen so a merely weird domain
    # sits around 0.3-0.4 and a very suspicious one clears 0.6.
    c_depth = min(subdomain_depth / 4.0, 1.0) * 0.20
    c_hyphen = min(hyphens / 4.0, 1.0) * 0.15
    c_digits = min(digit_ratio / 0.3, 1.0) * 0.15
    c_length = min(max(length - 20, 0) / 30.0, 1.0) * 0.10
    c_tld = risky_tld * 0.20
    c_puny = puny * 0.15
    # Fresh cert (<= 1 day) adds; older certs contribute less.
    c_fresh = (1.0 if age_days <= 1.0 else max(0.0, 1.0 - (age_days - 1.0) / 7.0)) * 0.05

    score = c_depth + c_hyphen + c_digits + c_length + c_tld + c_puny + c_fresh
    features = {
        "subdomain_depth": float(subdomain_depth),
        "hyphen_count": float(hyphens),
        "digit_ratio": digit_ratio,
        "length": float(length),
        "risky_tld": risky_tld,
        "punycode": puny,
        "cert_age_days": age_days,
    }
    return round(min(score, 1.0), 4), features


__all__ = [
    "STRUCTURAL_FEATURE_NAMES",
    "extract_registrable",
    "tld_of",
    "tokens_of",
    "levenshtein",
    "structural_score",
]
