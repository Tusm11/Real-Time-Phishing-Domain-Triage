"""
Ingester: subscribes to the public Certstream WebSocket, extracts certificate
events, and pushes a compact record onto Redis for the filter to consume.

Design notes:
- One Redis list (RAW_QUEUE) is the hand-off. LPUSH from here, BRPOP in filter.
- We extract only the fields the filter actually uses. Full cert blobs are
  big and we don't need them downstream.
- Certstream reconnects are expected; the loop runs forever and backs off
  exponentially on failures.
- Prometheus metrics are served from a tiny aiohttp app on METRICS_PORT.
  Health check at /health returns 200 as long as the event loop is alive.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from typing import Any

import redis.asyncio as aioredis
import websockets
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

# --- Config -----------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RAW_QUEUE = os.getenv("RAW_QUEUE", "raw_certs")
CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
METRICS_PORT = int(os.getenv("METRICS_PORT", "9101"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MAX_QUEUE_LEN = int(os.getenv("MAX_QUEUE_LEN", "50000"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s ingester %(message)s",
)
log = logging.getLogger("ingester")

# --- Metrics ----------------------------------------------------------------

CERTS_INGESTED = Counter(
    "certs_ingested_total", "Certificate events pushed to raw queue"
)
CERTS_DROPPED = Counter(
    "certs_dropped_total", "Certificate events dropped", ["reason"]
)
WS_RECONNECTS = Counter(
    "ws_reconnects_total", "Certstream reconnect attempts"
)
QUEUE_DEPTH = Gauge(
    "raw_queue_depth", "Current depth of the raw_certs Redis list"
)
LAST_EVENT_TS = Gauge(
    "ingester_last_event_timestamp", "Unix ts of the last event pushed"
)

# --- Core -------------------------------------------------------------------

def extract_record(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the fields we care about from a Certstream message.

    Returns None for heartbeats and malformed messages.
    """
    if msg.get("message_type") != "certificate_update":
        return None

    data = msg.get("data") or {}
    leaf = (data.get("leaf_cert") or {})
    all_domains = leaf.get("all_domains") or []
    if not all_domains:
        return None

    subject = leaf.get("subject") or {}
    issuer = (leaf.get("issuer") or {}).get("O") or ""
    not_before = leaf.get("not_before")
    seen_at = data.get("seen", time.time())

    return {
        "domains": all_domains,            # list[str]
        "cn": subject.get("CN") or "",
        "issuer": issuer,
        "not_before": not_before,
        "seen_at": seen_at,
        "source": data.get("source", {}).get("name", "certstream"),
    }


async def push_record(r: aioredis.Redis, record: dict[str, Any]) -> None:
    """LPUSH onto the raw queue with a soft cap to prevent runaway memory."""
    depth = await r.llen(RAW_QUEUE)
    if depth >= MAX_QUEUE_LEN:
        CERTS_DROPPED.labels(reason="queue_full").inc()
        return
    await r.lpush(RAW_QUEUE, json.dumps(record, separators=(",", ":")))
    CERTS_INGESTED.inc()
    LAST_EVENT_TS.set(time.time())


async def consume_certstream(r: aioredis.Redis, stop: asyncio.Event) -> None:
    """Main WS loop with exponential backoff on disconnect."""
    backoff = 1.0
    while not stop.is_set():
        try:
            log.info("Connecting to %s", CERTSTREAM_URL)
            async with websockets.connect(
                CERTSTREAM_URL,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5,
                max_size=4 * 1024 * 1024,
            ) as ws:
                backoff = 1.0
                WS_RECONNECTS.inc()
                async for raw in ws:
                    if stop.is_set():
                        break
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        CERTS_DROPPED.labels(reason="bad_json").inc()
                        continue
                    record = extract_record(msg)
                    if record is None:
                        CERTS_DROPPED.labels(reason="heartbeat_or_empty").inc()
                        continue
                    await push_record(r, record)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - we want to log and retry everything
            log.warning("Certstream connection error: %s; backoff=%.1fs", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0)


async def queue_depth_sampler(r: aioredis.Redis, stop: asyncio.Event) -> None:
    """Refresh the queue-depth gauge every second."""
    while not stop.is_set():
        try:
            QUEUE_DEPTH.set(await r.llen(RAW_QUEUE))
        except Exception as exc:  # noqa: BLE001
            log.debug("Depth sample failed: %s", exc)
        await asyncio.sleep(1.0)


# --- HTTP (metrics + health) -----------------------------------------------

async def metrics_handler(_: web.Request) -> web.Response:
    # Can't use content_type=CONTENT_TYPE_LATEST — aiohttp rejects the charset
    # suffix prometheus_client puts in that constant. Set the header directly.
    return web.Response(body=generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})


async def health_handler(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)
    return app


# --- Entrypoint -------------------------------------------------------------

async def main() -> None:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", METRICS_PORT)
    await site.start()
    log.info("Metrics + health on :%d", METRICS_PORT)

    tasks = [
        asyncio.create_task(consume_certstream(r, stop), name="certstream"),
        asyncio.create_task(queue_depth_sampler(r, stop), name="depth"),
    ]
    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await runner.cleanup()
    await r.aclose()
    log.info("Shutdown clean")


if __name__ == "__main__":
    asyncio.run(main())
