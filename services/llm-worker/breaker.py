"""
Minimal async circuit breaker.

States: closed -> open -> half_open -> closed
  - closed:    calls pass through; failures increment a counter
  - open:      calls short-circuit with BreakerOpen; after reset_seconds,
               the next call becomes a half-open probe
  - half_open: one probe at a time; success -> closed, failure -> open

Separate from the retry logic in the Groq client. Retries handle transient
blips within one call; the breaker handles sustained failure across calls.
"""

from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


class BreakerOpen(Exception):
    """Raised when the breaker is open and refuses the call."""


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self._state = "closed"
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()
        self._probe_lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        async with self._lock:
            if self._state == "open":
                assert self._opened_at is not None
                if time.monotonic() - self._opened_at >= self.reset_seconds:
                    self._state = "half_open"
                else:
                    raise BreakerOpen("circuit open")

        if self._state == "half_open":
            # Only one probe at a time.
            async with self._probe_lock:
                try:
                    result = await fn()
                except Exception:
                    await self._trip()
                    raise
                else:
                    await self._reset()
                    return result

        try:
            result = await fn()
        except Exception:
            await self._on_failure()
            raise
        else:
            await self._on_success()
            return result

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._state == "closed" and self._failures >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state == "closed":
                self._failures = 0

    async def _trip(self) -> None:
        async with self._lock:
            self._state = "open"
            self._opened_at = time.monotonic()
            self._failures = self.failure_threshold

    async def _reset(self) -> None:
        async with self._lock:
            self._state = "closed"
            self._failures = 0
            self._opened_at = None
