"""
Rule-based classifier used when the circuit breaker is open or the LLM
call fails outright. Keeps the pipeline producing *some* verdict so that
downstream monitoring and the dashboard stay useful during a Groq outage.

Logic is a weighted vote over the signals the filter already computed:
  - low Levenshtein distance to a brand (a <= 1)
  - high structural score (b >= 0.75)
  - high embedding similarity (c >= 0.85)
  - risky TLD or punycode in features

Three or more "yes" votes -> phishing; one or two -> suspicious; zero -> benign.
Confidence is always capped at 0.7 so the UI can tell at a glance that it
came from the fallback.
"""

from __future__ import annotations

from typing import Any


def rule_based_verdict(candidate: dict[str, Any]) -> tuple[str, float, str]:
    fs = candidate.get("filter_scores", {}) or {}
    feats = candidate.get("features", {}) or {}

    votes = 0
    reasons: list[str] = []

    a = fs.get("a", 999)
    if isinstance(a, (int, float)) and a <= 1:
        votes += 1
        reasons.append(f"a<=1 (dist={a})")

    b = fs.get("b", 0.0)
    if isinstance(b, (int, float)) and b >= 0.75:
        votes += 1
        reasons.append(f"b>=0.75 ({b:.2f})")

    c = fs.get("c", 0.0)
    if isinstance(c, (int, float)) and c >= 0.85:
        votes += 1
        reasons.append(f"c>=0.85 ({c:.2f})")

    if feats.get("risky_tld") == 1.0 or feats.get("punycode") == 1.0:
        votes += 1
        reasons.append("risky_tld_or_puny")

    if votes >= 3:
        verdict, conf = "phishing", 0.65
    elif votes >= 1:
        verdict, conf = "suspicious", 0.5
    else:
        verdict, conf = "benign", 0.4

    reasoning = f"fallback vote={votes}; " + ", ".join(reasons) if reasons else f"fallback vote=0"
    return verdict, conf, reasoning
