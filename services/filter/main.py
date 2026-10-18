"""
Filter: pops raw cert records from Redis, runs three progressively heavier
stages, and pushes survivors onto the triage queue for the LLM tier.

Target drop rate: ~99.95% end-to-end so Groq spend stays bounded.

Stage A - watchlist substring + Levenshtein <= 2
    Cheap. Rejects anything whose domain tokens don't look like a brand.
Stage B - structural score
    Hand-built features from the domain string: subdomain depth, hyphen
    count, digit ratio, TLD class, punycode, cert age. Threshold 0.6.
Stage C - embedding cosine similarity
    sentence-transformers/all-MiniLM-L6-v2 against pre-computed brand
    embeddings. Threshold 0.75.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from scoring import (
    STRUCTURAL_FEATURE_NAMES,
    extract_registrable,
    levenshtein,
    structural_score,
    tokens_of,
)

# --- Config -----------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RAW_QUEUE = os.getenv("RAW_QUEUE", "raw_certs")
TRIAGE_QUEUE = os.getenv("TRIAGE_QUEUE", "triage_candidates")
BRAND_WATCHLIST = [
    b.strip().lower()
    for b in os.getenv(
        "BRAND_WATCHLIST", "sbi,hdfc,icici,axis,kotak,paytm,phonepe,zerodha,groww"
    ).split(",")
    if b.strip()
]
STAGE_B_THRESHOLD = float(os.getenv("STAGE_B_THRESHOLD", "0.6"))
STAGE_C_THRESHOLD = float(os.getenv("STAGE_C_THRESHOLD", "0.75"))
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
METRICS_PORT = int(os.getenv("METRICS_PORT", "9102"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
WORKERS = int(os.getenv("WORKERS", "4"))
LEVENSHTEIN_MAX = int(os.getenv("LEVENSHTEIN_MAX", "2"))
MAX_TRIAGE_LEN = int(os.getenv("MAX_TRIAGE_LEN", "10000"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s filter %(message)s",
)
log = logging.getLogger("filter")

# --- Metrics ----------------------------------------------------------------

PASSED = Counter("filter_passed_total", "Records passed a stage", ["stage"])
DROPPED = Counter("filter_dropped_total", "Records dropped at a stage", ["stage", "reason"])
STAGE_LATENCY = Histogram(
    "filter_stage_latency_seconds",
    "Latency per stage",
    ["stage"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)
TRIAGE_DEPTH = Gauge("triage_queue_depth", "Depth of the triage_candidates queue")

# --- Models ----------------------------------------------------------------

@dataclass
class StageAResult:
    passed: bool
    matched_brand: str | None
    best_token: str | None
    distance: int | None


@dataclass
class StageBResult:
    passed: bool
    score: float
    features: dict[str, float]


@dataclass
class StageCResult:
    passed: bool
    similarity: float


# --- Stage A ---------------------------------------------------------------

def stage_a(domain: str, brands: list[str], max_distance: int = LEVENSHTEIN_MAX) -> StageAResult:
    """Watchlist substring OR Levenshtein <= max_distance against brand tokens.

    Operates on the registrable name's tokens (split on '-' and '.'), so
    "icici-login.site" matches "icici" at distance 0.
    """
    reg = extract_registrable(domain)
    toks = tokens_of(reg)
    best_brand: str | None = None
    best_token: str | None = None
    best_dist: int | None = None
    for brand in brands:
        for tok in toks:
            if brand in tok or tok in brand:
                return StageAResult(True, brand, tok, 0)
            d = levenshtein(brand, tok, max_distance)
            if d <= max_distance:
                if best_dist is None or d < best_dist:
                    best_brand, best_token, best_dist = brand, tok, d
    return StageAResult(best_brand is not None, best_brand, best_token, best_dist)


# --- Stage B ---------------------------------------------------------------

def stage_b(domain: str, not_before: int | float | None) -> StageBResult:
    score, features = structural_score(domain, not_before=not_before)
    return StageBResult(score >= STAGE_B_THRESHOLD, score, features)


# --- Stage C ---------------------------------------------------------------

class EmbeddingScorer:
    """Thin wrapper around sentence-transformers; initialized lazily so the
    model only downloads once per container. Brand embeddings cached in RAM."""

    def __init__(self, model_name: str, brands: list[str]):
        self.model_name = model_name
        self.brands = brands
        self._model = None
        self._brand_vecs = None

    def _lazy_init(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer  # local import

        log.info("Loading embedding model: %s", self.model_name)
        self._model = SentenceTransformer(self.model_name)
        self._brand_vecs = self._model.encode(
            self.brands, normalize_embeddings=True, convert_to_numpy=True
        )
        log.info("Brand embeddings ready: %d vectors", len(self.brands))

    def score(self, domain: str) -> tuple[float, str]:
        """Return (max_cosine_similarity, best_matching_brand)."""
        self._lazy_init()
        reg = extract_registrable(domain)
        vec = self._model.encode([reg], normalize_embeddings=True, convert_to_numpy=True)[0]
        sims = self._brand_vecs @ vec  # cosine since both are normalized
        idx = int(sims.argmax())
        return float(sims[idx]), self.brands[idx]


# --- Pipeline --------------------------------------------------------------

async def process_record(
    r: aioredis.Redis, record: dict[str, Any], scorer: EmbeddingScorer
) -> None:
    """Run A -> B -> C. Push survivors onto TRIAGE_QUEUE."""
    for domain in record.get("domains", []):
        # Stage A
        with STAGE_LATENCY.labels(stage="a").time():
            a = stage_a(domain, BRAND_WATCHLIST)
        if not a.passed:
            DROPPED.labels(stage="a", reason="no_brand_match").inc()
            continue
        PASSED.labels(stage="a").inc()

        # Stage B
        with STAGE_LATENCY.labels(stage="b").time():
            b = stage_b(domain, record.get("not_before"))
        if not b.passed:
            DROPPED.labels(stage="b", reason="low_structural").inc()
            continue
        PASSED.labels(stage="b").inc()

        # Stage C
        with STAGE_LATENCY.labels(stage="c").time():
            sim, best_brand = scorer.score(domain)
        c_passed = sim >= STAGE_C_THRESHOLD
        if not c_passed:
            DROPPED.labels(stage="c", reason="low_similarity").inc()
            continue
        PASSED.labels(stage="c").inc()

        candidate = {
            "domain": domain,
            "cert_issuer": record.get("issuer", ""),
            "cert_not_before": record.get("not_before"),
            "seen_at": record.get("seen_at", time.time()),
            "matched_brand": best_brand,
            "filter_scores": {
                "a": a.distance if a.distance is not None else 999,
                "b": round(b.score, 4),
                "c": round(sim, 4),
            },
            "features": {k: round(v, 4) for k, v in b.features.items()},
        }
        depth = await r.llen(TRIAGE_QUEUE)
        if depth >= MAX_TRIAGE_LEN:
            DROPPED.labels(stage="post", reason="triage_full").inc()
            continue
        await r.lpush(TRIAGE_QUEUE, json.dumps(candidate, separators=(",", ":")))


async def worker(r: aioredis.Redis, scorer: EmbeddingScorer, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            res = await r.brpop(RAW_QUEUE, timeout=1)
            if res is None:
                continue
            _, raw = res
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                DROPPED.labels(stage="pre", reason="bad_json").inc()
                continue
            await process_record(r, record, scorer)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("Worker loop error: %s", exc)


async def depth_sampler(r: aioredis.Redis, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            TRIAGE_DEPTH.set(await r.llen(TRIAGE_QUEUE))
        except Exception as exc:  # noqa: BLE001
            log.debug("Depth sampler: %s", exc)
        await asyncio.sleep(1.0)


# --- HTTP ------------------------------------------------------------------

async def metrics_handler(_: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})


async def health_handler(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "features": STRUCTURAL_FEATURE_NAMES})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)
    return app


# --- Entrypoint ------------------------------------------------------------

async def main() -> None:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    scorer = EmbeddingScorer(EMBEDDING_MODEL, BRAND_WATCHLIST)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", METRICS_PORT)
    await site.start()
    log.info("Metrics + health on :%d", METRICS_PORT)
    log.info("Starting %d worker(s), brands=%s", WORKERS, BRAND_WATCHLIST)

    tasks = [asyncio.create_task(worker(r, scorer, stop), name=f"w{i}") for i in range(WORKERS)]
    tasks.append(asyncio.create_task(depth_sampler(r, stop), name="depth"))

    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await runner.cleanup()
    await r.aclose()
    log.info("Shutdown clean")


if __name__ == "__main__":
    asyncio.run(main())
