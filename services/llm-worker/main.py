"""
LLM worker: pulls candidates off the triage queue, asks Groq to classify,
writes a verdict row to Postgres. Resilience stack:

  - token-aware rate limiter that reads Groq's own headers
  - 10s hard timeout per request
  - 3x exponential backoff honoring Retry-After
  - circuit breaker trips on sustained 429/5xx
  - rule-based fallback classifier when breaker is open

Every call logs tokens in/out, latency, status, model_version; the row
records whether the verdict came from the LLM or the fallback.
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

import asyncpg
import httpx
import redis.asyncio as aioredis
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from breaker import CircuitBreaker, BreakerOpen
from fallback import rule_based_verdict
from limiter import GroqRateLimiter

# --- Config ----------------------------------------------------------------

WORKER_ID = os.getenv("WORKER_ID", "0")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TRIAGE_QUEUE = os.getenv("TRIAGE_QUEUE", "triage_candidates")
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "postgresql://phish:phish@postgres:5432/phish")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_URL = os.getenv("GROQ_URL", "https://api.groq.com/openai/v1/chat/completions")
GROQ_TIMEOUT_SECONDS = float(os.getenv("GROQ_TIMEOUT_SECONDS", "10"))
GROQ_MAX_RETRIES = int(os.getenv("GROQ_MAX_RETRIES", "3"))
BREAKER_FAILURE_THRESHOLD = int(os.getenv("BREAKER_FAILURE_THRESHOLD", "5"))
BREAKER_RESET_SECONDS = float(os.getenv("BREAKER_RESET_SECONDS", "30"))
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8000"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "9103"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=LOG_LEVEL,
    format=f"%(asctime)s %(levelname)s llm-worker[{WORKER_ID}] %(message)s",
)
log = logging.getLogger("llm-worker")

# --- Metrics ---------------------------------------------------------------

LLM_REQUESTS = Counter(
    "llm_requests_total", "LLM API calls", ["status", "worker"]
)
LLM_LATENCY = Histogram(
    "llm_latency_seconds",
    "LLM request latency",
    ["worker"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 10.0),
)
LLM_TOKENS = Counter(
    "llm_tokens_total", "Tokens used", ["direction", "worker"]
)
GROQ_REMAINING = Gauge(
    "groq_rate_remaining", "Groq rate-limit remaining headers", ["type", "worker"]
)
BREAKER_STATE = Gauge(
    "breaker_state", "0=closed 1=half_open 2=open", ["worker"]
)
VERDICT_TOTAL = Counter(
    "verdict_total", "Verdicts emitted", ["verdict", "source"]
)

# --- Prompt ---------------------------------------------------------------

SYSTEM_PROMPT = """You classify suspicious domains for a phishing-triage pipeline.
Decide whether the domain is a phishing lookalike targeting a specific Indian financial brand.

Reply ONLY with a JSON object:
{
  "verdict": "phishing" | "suspicious" | "benign",
  "confidence": 0.0-1.0,
  "mimicked_brand": "<brand name or empty>",
  "reasoning": "<one short sentence>"
}

Use "phishing" when brand mimicry is clear (lookalike spelling, brand+login/verify/secure/support,
risky TLD, fresh cert). Use "suspicious" when it is plausible but ambiguous. Use "benign" when the
domain is unrelated or looks legitimate."""


def build_user_prompt(candidate: dict[str, Any]) -> str:
    return json.dumps(
        {
            "domain": candidate["domain"],
            "cert_issuer": candidate.get("cert_issuer", ""),
            "cert_not_before": candidate.get("cert_not_before"),
            "filter_scores": candidate.get("filter_scores", {}),
            "matched_brand": candidate.get("matched_brand"),
            "features": candidate.get("features", {}),
        },
        separators=(",", ":"),
    )


# --- Groq client ----------------------------------------------------------

@dataclass
class LLMResponse:
    verdict: str
    confidence: float
    mimicked_brand: str
    reasoning: str
    model_version: str
    tokens_in: int
    tokens_out: int


class GroqClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        url: str,
        timeout_s: float,
        max_retries: int,
        limiter: GroqRateLimiter,
    ):
        self.api_key = api_key
        self.model = model
        self.url = url
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.limiter = limiter
        self._client = httpx.AsyncClient(timeout=timeout_s)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def classify(self, candidate: dict[str, Any]) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is empty — set it in .env")

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(candidate)},
            ],
            "temperature": 0.0,
            "max_tokens": 200,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        attempt = 0
        while True:
            attempt += 1
            await self.limiter.wait()
            t0 = time.perf_counter()
            try:
                resp = await self._client.post(self.url, headers=headers, json=payload)
            except httpx.TimeoutException:
                LLM_REQUESTS.labels(status="timeout", worker=WORKER_ID).inc()
                if attempt > self.max_retries:
                    raise
                await asyncio.sleep(min(2 ** (attempt - 1), 8))
                continue
            except httpx.HTTPError as exc:
                LLM_REQUESTS.labels(status="transport_err", worker=WORKER_ID).inc()
                if attempt > self.max_retries:
                    raise
                log.warning("Transport error attempt %d: %s", attempt, exc)
                await asyncio.sleep(min(2 ** (attempt - 1), 8))
                continue

            elapsed = time.perf_counter() - t0
            LLM_LATENCY.labels(worker=WORKER_ID).observe(elapsed)
            self.limiter.update_from_headers(resp.headers)
            self._export_remaining(resp.headers)

            if resp.status_code == 429 or resp.status_code >= 500:
                LLM_REQUESTS.labels(
                    status=f"http_{resp.status_code}", worker=WORKER_ID
                ).inc()
                if attempt > self.max_retries:
                    raise RuntimeError(f"Groq {resp.status_code}: {resp.text[:200]}")
                retry_after = _parse_retry_after(resp.headers)
                sleep_s = retry_after if retry_after else min(2 ** (attempt - 1), 8)
                log.warning(
                    "Groq %d; retry in %.1fs (attempt %d)",
                    resp.status_code,
                    sleep_s,
                    attempt,
                )
                await asyncio.sleep(sleep_s)
                continue

            if resp.status_code != 200:
                LLM_REQUESTS.labels(
                    status=f"http_{resp.status_code}", worker=WORKER_ID
                ).inc()
                raise RuntimeError(f"Groq {resp.status_code}: {resp.text[:200]}")

            LLM_REQUESTS.labels(status="ok", worker=WORKER_ID).inc()
            return self._parse_response(resp.json())

    def _export_remaining(self, headers: httpx.Headers) -> None:
        for h_key, label in [
            ("x-ratelimit-remaining-requests", "requests"),
            ("x-ratelimit-remaining-tokens", "tokens"),
        ]:
            v = headers.get(h_key)
            if v is not None:
                try:
                    GROQ_REMAINING.labels(type=label, worker=WORKER_ID).set(float(v))
                except ValueError:
                    pass

    def _parse_response(self, body: dict[str, Any]) -> LLMResponse:
        choice = body["choices"][0]["message"]["content"] or ""
        parsed = _loose_json(choice)
        if parsed is None:
            raise RuntimeError(f"LLM returned non-JSON: {choice[:200]}")

        usage = body.get("usage", {}) or {}
        tin = int(usage.get("prompt_tokens", 0))
        tout = int(usage.get("completion_tokens", 0))
        LLM_TOKENS.labels(direction="in", worker=WORKER_ID).inc(tin)
        LLM_TOKENS.labels(direction="out", worker=WORKER_ID).inc(tout)

        verdict = str(parsed.get("verdict", "suspicious")).lower()
        if verdict not in {"phishing", "suspicious", "benign"}:
            verdict = "suspicious"
        return LLMResponse(
            verdict=verdict,
            confidence=float(parsed.get("confidence", 0.5)),
            mimicked_brand=str(parsed.get("mimicked_brand", "") or ""),
            reasoning=str(parsed.get("reasoning", ""))[:500],
            model_version=str(body.get("model", self.model)),
            tokens_in=tin,
            tokens_out=tout,
        )


def _loose_json(text: str) -> dict[str, Any] | None:
    """Extract the first balanced {...} block from text and json.loads it."""
    text = text.strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _parse_retry_after(headers: httpx.Headers) -> float | None:
    v = headers.get("retry-after")
    if v is None:
        return None
    try:
        return float(v)
    except ValueError:
        return None


# --- DB write -------------------------------------------------------------

INSERT_SQL = """
INSERT INTO verdicts (
    domain, cert_issuer, cert_not_before, seen_at,
    filter_a, filter_b, filter_c,
    matched_brand, verdict, confidence, reasoning,
    model_version, source
) VALUES ($1,$2,to_timestamp($3),to_timestamp($4),$5,$6,$7,$8,$9,$10,$11,$12,$13)
"""


async def persist_verdict(
    pool: asyncpg.Pool,
    candidate: dict[str, Any],
    verdict: str,
    confidence: float,
    mimicked_brand: str,
    reasoning: str,
    model_version: str,
    source: str,
) -> None:
    fs = candidate.get("filter_scores", {})
    async with pool.acquire() as conn:
        await conn.execute(
            INSERT_SQL,
            candidate["domain"],
            candidate.get("cert_issuer", ""),
            float(candidate.get("cert_not_before") or 0) or None,
            float(candidate.get("seen_at", time.time())),
            float(fs.get("a", 999)),
            float(fs.get("b", 0.0)),
            float(fs.get("c", 0.0)),
            mimicked_brand or candidate.get("matched_brand", ""),
            verdict,
            float(confidence),
            reasoning,
            model_version,
            source,
        )


# --- Worker loop ----------------------------------------------------------

async def process_one(
    r: aioredis.Redis,
    pool: asyncpg.Pool,
    groq: GroqClient,
    breaker: CircuitBreaker,
    candidate: dict[str, Any],
) -> None:
    try:
        async def _call() -> LLMResponse:
            return await groq.classify(candidate)

        resp = await breaker.call(_call)
        await persist_verdict(
            pool, candidate,
            verdict=resp.verdict,
            confidence=resp.confidence,
            mimicked_brand=resp.mimicked_brand,
            reasoning=resp.reasoning,
            model_version=resp.model_version,
            source="llm",
        )
        VERDICT_TOTAL.labels(verdict=resp.verdict, source="llm").inc()
    except BreakerOpen:
        v, conf, reason = rule_based_verdict(candidate)
        await persist_verdict(
            pool, candidate,
            verdict=v, confidence=conf, mimicked_brand=candidate.get("matched_brand", ""),
            reasoning=reason, model_version="fallback", source="fallback",
        )
        VERDICT_TOTAL.labels(verdict=v, source="fallback").inc()
    except Exception as exc:  # noqa: BLE001
        log.exception("Classify failed: %s", exc)
        v, conf, reason = rule_based_verdict(candidate)
        await persist_verdict(
            pool, candidate,
            verdict=v, confidence=conf, mimicked_brand=candidate.get("matched_brand", ""),
            reasoning=f"error: {exc.__class__.__name__}; {reason}",
            model_version="fallback", source="fallback",
        )
        VERDICT_TOTAL.labels(verdict=v, source="fallback").inc()


async def worker_loop(
    r: aioredis.Redis,
    pool: asyncpg.Pool,
    groq: GroqClient,
    breaker: CircuitBreaker,
    stop: asyncio.Event,
) -> None:
    while not stop.is_set():
        try:
            res = await r.brpop(TRIAGE_QUEUE, timeout=1)
            if res is None:
                BREAKER_STATE.labels(worker=WORKER_ID).set(_state_num(breaker.state))
                continue
            _, raw = res
            try:
                candidate = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("Bad JSON on triage queue; dropping")
                continue
            await process_one(r, pool, groq, breaker, candidate)
            BREAKER_STATE.labels(worker=WORKER_ID).set(_state_num(breaker.state))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("Worker loop: %s", exc)
            await asyncio.sleep(1.0)


def _state_num(state: str) -> int:
    return {"closed": 0, "half_open": 1, "open": 2}.get(state, 0)


# --- HTTP -----------------------------------------------------------------

async def metrics_handler(_: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})


async def health_handler(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "worker": WORKER_ID})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)
    return app


# --- Entrypoint -----------------------------------------------------------

async def main() -> None:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=4)
    limiter = GroqRateLimiter()
    groq = GroqClient(
        api_key=GROQ_API_KEY,
        model=GROQ_MODEL,
        url=GROQ_URL,
        timeout_s=GROQ_TIMEOUT_SECONDS,
        max_retries=GROQ_MAX_RETRIES,
        limiter=limiter,
    )
    breaker = CircuitBreaker(
        failure_threshold=BREAKER_FAILURE_THRESHOLD,
        reset_seconds=BREAKER_RESET_SECONDS,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    # Health server on HEALTH_PORT; metrics on METRICS_PORT.
    health_runner = web.AppRunner(build_app())
    await health_runner.setup()
    await web.TCPSite(health_runner, "0.0.0.0", HEALTH_PORT).start()

    metrics_runner = web.AppRunner(build_app())
    await metrics_runner.setup()
    await web.TCPSite(metrics_runner, "0.0.0.0", METRICS_PORT).start()

    log.info(
        "Worker %s ready. model=%s health=:%d metrics=:%d",
        WORKER_ID, GROQ_MODEL, HEALTH_PORT, METRICS_PORT,
    )

    task = asyncio.create_task(worker_loop(r, pool, groq, breaker, stop))
    await stop.wait()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    await groq.aclose()
    await pool.close()
    await r.aclose()
    await health_runner.cleanup()
    await metrics_runner.cleanup()
    log.info("Shutdown clean")


if __name__ == "__main__":
    asyncio.run(main())
