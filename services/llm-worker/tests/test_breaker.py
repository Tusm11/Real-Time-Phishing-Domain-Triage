"""Breaker state machine — pure, no I/O."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from breaker import BreakerOpen, CircuitBreaker  # noqa: E402


@pytest.mark.asyncio
async def test_closed_passes_through():
    b = CircuitBreaker(failure_threshold=3, reset_seconds=1.0)

    async def ok():
        return 42

    assert await b.call(ok) == 42
    assert b.state == "closed"


@pytest.mark.asyncio
async def test_opens_after_threshold():
    b = CircuitBreaker(failure_threshold=3, reset_seconds=1.0)

    async def boom():
        raise RuntimeError("nope")

    for _ in range(3):
        with pytest.raises(RuntimeError):
            await b.call(boom)
    assert b.state == "open"


@pytest.mark.asyncio
async def test_open_short_circuits():
    b = CircuitBreaker(failure_threshold=1, reset_seconds=10.0)

    async def boom():
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        await b.call(boom)
    with pytest.raises(BreakerOpen):
        await b.call(boom)


@pytest.mark.asyncio
async def test_half_open_success_closes():
    b = CircuitBreaker(failure_threshold=1, reset_seconds=0.05)

    async def boom():
        raise RuntimeError("x")

    async def ok():
        return "ok"

    with pytest.raises(RuntimeError):
        await b.call(boom)
    assert b.state == "open"
    await asyncio.sleep(0.1)
    assert await b.call(ok) == "ok"
    assert b.state == "closed"


@pytest.mark.asyncio
async def test_half_open_failure_reopens():
    b = CircuitBreaker(failure_threshold=1, reset_seconds=0.05)

    async def boom():
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        await b.call(boom)
    await asyncio.sleep(0.1)
    with pytest.raises(RuntimeError):
        await b.call(boom)
    assert b.state == "open"
