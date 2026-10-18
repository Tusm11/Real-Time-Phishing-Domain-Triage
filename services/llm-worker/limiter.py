"""
Token-aware rate limiter that reads Groq's response headers:

  x-ratelimit-remaining-requests
  x-ratelimit-remaining-tokens
  x-ratelimit-reset-requests  (seconds)
  x-ratelimit-reset-tokens    (seconds)

When remaining dips near zero, wait() blocks until reset is likely done.
This is intentionally pessimistic: we'd rather lose a tiny bit of throughput
than hit a 429 and burn a retry.
"""

from __future__ import annotations

import asyncio
import logging
import time

log = logging.getLogger("llm-worker.limiter")


class GroqRateLimiter:
    def __init__(self, min_margin_requests: int = 2, min_margin_tokens: int = 1500):
        self.min_margin_requests = min_margin_requests
        self.min_margin_tokens = min_margin_tokens
        self._remaining_requests: float | None = None
        self._remaining_tokens: float | None = None
        self._reset_requests_at: float = 0.0  # monotonic
        self._reset_tokens_at: float = 0.0
        self._lock = asyncio.Lock()

    def update_from_headers(self, headers) -> None:
        now = time.monotonic()
        rr = headers.get("x-ratelimit-remaining-requests")
        rt = headers.get("x-ratelimit-remaining-tokens")
        resetr = headers.get("x-ratelimit-reset-requests")
        resett = headers.get("x-ratelimit-reset-tokens")
        try:
            if rr is not None:
                self._remaining_requests = float(rr)
            if rt is not None:
                self._remaining_tokens = float(rt)
            if resetr is not None:
                self._reset_requests_at = now + float(resetr)
            if resett is not None:
                self._reset_tokens_at = now + float(resett)
        except ValueError:
            pass

    async def wait(self) -> None:
        """Block until it's safe to send another request."""
        async with self._lock:
            delay = 0.0
            now = time.monotonic()
            if (
                self._remaining_requests is not None
                and self._remaining_requests <= self.min_margin_requests
            ):
                delay = max(delay, self._reset_requests_at - now)
            if (
                self._remaining_tokens is not None
                and self._remaining_tokens <= self.min_margin_tokens
            ):
                delay = max(delay, self._reset_tokens_at - now)
            if delay > 0:
                # Cap at 65s so a quota reset at ~60s is always covered.
                log.info("Rate-limiter pausing %.2fs", delay)
                await asyncio.sleep(min(delay, 65.0))
