"""Tests for kernel/_driver_exec.py: fallback, deadlines, and fault capture."""

from __future__ import annotations

import asyncio

import pytest

from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.errors import DriverError
from weaver_kernel.kernel._driver_exec import execute_with_fallback, resolve_invoke_timeout
from weaver_kernel.models import RawResult, RoutePlan


class _OKDriver:
    """A driver that returns a fixed payload."""

    def __init__(self, driver_id: str = "ok", *, payload: object = "ok") -> None:
        self._driver_id = driver_id
        self._payload = payload

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        return RawResult(capability_id=ctx.capability_id, data=self._payload)


class _RaisingDriver:
    """A driver whose ``execute`` raises a caller-supplied exception."""

    def __init__(self, driver_id: str, exc: Exception) -> None:
        self._driver_id = driver_id
        self._exc = exc

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        raise self._exc


class _SlowDriver:
    """A driver that sleeps longer than any reasonable test deadline."""

    def __init__(self, driver_id: str = "slow") -> None:
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        await asyncio.sleep(1.0)
        return RawResult(capability_id=ctx.capability_id, data="late")


def _ctx() -> ExecutionContext:
    return ExecutionContext(capability_id="cap.x", principal_id="u1")


def _plan(*driver_ids: str) -> RoutePlan:
    return RoutePlan(capability_id="cap.x", driver_ids=list(driver_ids))


# ── resolve_invoke_timeout ─────────────────────────────────────────────────────


def test_resolve_invoke_timeout_absent_is_none() -> None:
    assert resolve_invoke_timeout({}) is None


def test_resolve_invoke_timeout_valid_returns_float() -> None:
    assert resolve_invoke_timeout({"invoke_timeout_s": 5}) == 5.0


@pytest.mark.parametrize("bad", [0, -1, "5", True, [1]])
def test_resolve_invoke_timeout_invalid_raises(bad: object) -> None:
    with pytest.raises(DriverError, match="invoke_timeout_s"):
        resolve_invoke_timeout({"invoke_timeout_s": bad})


# ── execute_with_fallback: fault capture (#152) ────────────────────────────────


@pytest.mark.asyncio
async def test_unexpected_exception_is_captured_not_raised() -> None:
    """A non-DriverError from a driver becomes ``last_error``, not an escape (#152)."""
    boom = ValueError("boom")
    drivers = {"bad": _RaisingDriver("bad", boom)}
    raw, driver_id, last_error, fell_back = await execute_with_fallback(
        drivers, _plan("bad"), ctx=_ctx(), log_ctx={}
    )
    assert raw is None
    assert driver_id == "bad"  # last driver attempted, for audit attribution
    assert last_error is boom
    assert fell_back is True


@pytest.mark.asyncio
async def test_fallback_runs_after_unexpected_exception() -> None:
    """An unexpected exception is a failed attempt; the next driver still runs (#152)."""
    drivers = {
        "bad": _RaisingDriver("bad", RuntimeError("kaboom")),
        "good": _OKDriver("good", payload={"from": "good"}),
    }
    raw, driver_id, last_error, fell_back = await execute_with_fallback(
        drivers, _plan("bad", "good"), ctx=_ctx(), log_ctx={}
    )
    assert raw is not None and raw.data == {"from": "good"}
    assert driver_id == "good"
    assert last_error is None
    assert fell_back is True


# ── execute_with_fallback: deadline (#191) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_timeout_synthesizes_driver_error() -> None:
    drivers = {"slow": _SlowDriver("slow")}
    raw, driver_id, last_error, _ = await execute_with_fallback(
        drivers, _plan("slow"), ctx=_ctx(), log_ctx={}, timeout=0.01
    )
    assert raw is None
    assert isinstance(last_error, DriverError)
    assert "timed out after 0.01s" in str(last_error)


@pytest.mark.asyncio
async def test_timeout_then_fallback_succeeds() -> None:
    drivers = {"slow": _SlowDriver("slow"), "fast": _OKDriver("fast", payload="quick")}
    raw, driver_id, last_error, fell_back = await execute_with_fallback(
        drivers, _plan("slow", "fast"), ctx=_ctx(), log_ctx={}, timeout=0.01
    )
    assert raw is not None and raw.data == "quick"
    assert driver_id == "fast"
    assert fell_back is True


@pytest.mark.asyncio
async def test_fast_driver_under_deadline_succeeds() -> None:
    drivers = {"ok": _OKDriver("ok", payload=42)}
    raw, driver_id, last_error, fell_back = await execute_with_fallback(
        drivers, _plan("ok"), ctx=_ctx(), log_ctx={}, timeout=5.0
    )
    assert raw is not None and raw.data == 42
    assert driver_id == "ok"
    assert last_error is None
    assert fell_back is False
