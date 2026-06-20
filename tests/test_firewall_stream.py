"""Tests for the streaming firewall (:meth:`Firewall.apply_stream`) and
:meth:`Kernel.invoke_stream` (issue #47).

The streaming API is *additive*: non-streaming drivers still work via
:meth:`Driver.execute`. These tests pin the contracts the issue calls out:

* every chunk is firewalled (PII never leaks even in streaming mode),
* the last yielded :class:`Frame` carries ``is_final=True``,
* :meth:`Kernel.invoke_stream` falls back to a single-chunk stream when the
  driver does not implement :class:`StreamingDriver`,
* a ``StreamingDriver`` produces multiple firewalled chunks.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from weaver_kernel import (
    Budgets,
    Capability,
    CapabilityRegistry,
    Firewall,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
    StreamingDriver,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.models import CapabilityRequest, RawResult


class _FakeStreamingDriver:
    """Test double that yields predetermined chunks.

    Implements both :meth:`execute` (single-shot) and :meth:`execute_stream`
    so the kernel's streaming-capability check passes.
    """

    driver_id = "stream-test"

    def __init__(self, chunks: list[dict[str, Any]]) -> None:
        self._chunks = chunks

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        # Aggregated single-shot fallback: combine all chunks into one payload.
        combined = {"chunks": [dict(c) for c in self._chunks]}
        return RawResult(capability_id=ctx.capability_id, data=combined, provenance={})

    async def execute_stream(self, ctx: ExecutionContext) -> AsyncIterator[dict[str, Any]]:
        for chunk in self._chunks:
            yield chunk


def _build_streaming_kernel(
    driver: object,
) -> tuple[Kernel, Principal]:
    cap = Capability(
        capability_id="stream.read",
        name="read",
        description="Streamed read.",
        safety_class=SafetyClass.READ,
    )
    registry = CapabilityRegistry()
    registry.register(cap)
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="stream-test-secret"),
        router=StaticRouter(routes={"stream.read": [driver.driver_id]}),  # type: ignore[attr-defined]
    )
    kernel.register_driver(driver)  # type: ignore[arg-type]
    return kernel, Principal(principal_id="streamer", roles=["reader"])


@pytest.mark.asyncio
async def test_streaming_driver_protocol_runtime_check() -> None:
    """`isinstance(x, StreamingDriver)` must work since the kernel uses it."""
    streamer = _FakeStreamingDriver([{"foo": 1}])
    assert isinstance(streamer, StreamingDriver)

    # A plain non-streaming driver must NOT satisfy the protocol.
    plain = InMemoryDriver(driver_id="plain")
    assert not isinstance(plain, StreamingDriver)


@pytest.mark.asyncio
async def test_firewall_apply_stream_redacts_each_chunk() -> None:
    """`Firewall.apply_stream` runs each chunk through redaction.

    Synthetic PII / secret values must NOT appear in any yielded Frame's
    summary facts or table preview.
    """
    fw = Firewall(budgets=Budgets(max_chars=4000, max_rows=10, max_fields=10))

    async def chunks() -> AsyncIterator[dict[str, Any]]:
        yield {"rows": [{"public_id": 1, "email": "leaked@example.com"}]}
        yield {
            "rows": [{"public_id": 2, "api_token": "Bearer abc-secret-123"}],
            "__is_final__": True,
        }

    frames: list[Any] = []
    async for frame in fw.apply_stream(
        chunks(),
        action_id="act-1",
        capability_id="stream.read",
        principal_id="p1",
        principal_roles=["reader"],
        response_mode="table",
        constraints={"allowed_fields": ["public_id"]},
    ):
        frames.append(frame)

    assert len(frames) == 2
    assert frames[-1].is_final is True
    assert frames[0].is_final is False

    rendered = repr([f.table_preview for f in frames]) + repr([f.facts for f in frames])
    assert "leaked@example.com" not in rendered
    assert "abc-secret-123" not in rendered


@pytest.mark.asyncio
async def test_kernel_invoke_stream_with_streaming_driver_yields_multiple_frames() -> None:
    """A streaming driver produces one Frame per chunk; last has is_final."""
    driver = _FakeStreamingDriver(
        chunks=[
            {"chunk": 1, "row": {"id": "a"}},
            {"chunk": 2, "row": {"id": "b"}},
            {"chunk": 3, "row": {"id": "c"}, "__is_final__": True},
        ]
    )
    kernel, principal = _build_streaming_kernel(driver)
    req = CapabilityRequest(capability_id="stream.read", goal="t")
    token = kernel.get_token(req, principal, justification="")

    frames: list[Any] = []
    async for frame in kernel.invoke_stream(
        token, principal=principal, args={}, response_mode="summary"
    ):
        frames.append(frame)

    assert len(frames) == 3
    assert all(not f.is_final for f in frames[:-1])
    assert frames[-1].is_final is True
    # Every frame carries the same audit action_id.
    assert len({f.action_id for f in frames}) == 1


@pytest.mark.asyncio
async def test_kernel_invoke_stream_fallback_for_non_streaming_driver() -> None:
    """A driver without execute_stream yields exactly one final Frame."""
    plain = InMemoryDriver(driver_id="plain")

    def handler(ctx: ExecutionContext) -> dict[str, object]:
        return {"row_count": 7, "rows": [{"id": "x"}]}

    plain.register_handler("stream.read", handler)

    kernel, principal = _build_streaming_kernel(plain)
    req = CapabilityRequest(capability_id="stream.read", goal="t")
    token = kernel.get_token(req, principal, justification="")

    frames: list[Any] = []
    async for frame in kernel.invoke_stream(
        token, principal=principal, args={}, response_mode="summary"
    ):
        frames.append(frame)

    assert len(frames) == 1
    assert frames[0].is_final is True


@pytest.mark.asyncio
async def test_kernel_invoke_stream_emits_trace_event() -> None:
    """A streaming invocation records exactly one ActionTrace covering the stream."""
    driver = _FakeStreamingDriver(chunks=[{"chunk": 1, "__is_final__": True}])
    kernel, principal = _build_streaming_kernel(driver)
    req = CapabilityRequest(capability_id="stream.read", goal="t")
    token = kernel.get_token(req, principal, justification="")

    captured: list[Any] = []
    async for frame in kernel.invoke_stream(
        token, principal=principal, args={}, response_mode="summary"
    ):
        captured.append(frame)

    assert len(captured) >= 1
    trace = kernel.explain(captured[0].action_id)
    assert trace.capability_id == "stream.read"
    assert trace.principal_id == "streamer"
    assert trace.driver_id == "stream-test"
    assert trace.error is None


@pytest.mark.asyncio
async def test_stream_redaction_event_counts_any_frame_not_just_last() -> None:
    """Streaming redaction is counted if *any* frame warned, not only the last.

    `apply_stream` holds back a trailing overlap window, so a secret early in a
    long stream commits (and warns) in an early frame while the final frame is
    clean. The stats increment must reflect that earlier warning (#179 fix).
    """
    # Chunk 1: a contiguous email then >256 clean chars, so the email commits
    # (and warns) in the first emitted frame. Chunk 2 (final) is clean.
    driver = _FakeStreamingDriver(
        chunks=[
            {"text": "leaked@example.com " + ("x" * 300)},
            {"text": "all clear", "__is_final__": True},
        ]
    )
    kernel, principal = _build_streaming_kernel(driver)
    req = CapabilityRequest(capability_id="stream.read", goal="t")
    token = kernel.get_token(req, principal, justification="")

    frames: list[Any] = []
    async for frame in kernel.invoke_stream(
        token, principal=principal, args={}, response_mode="summary"
    ):
        frames.append(frame)

    # The secret warned on an earlier frame, and the final frame is clean.
    assert frames[0].warnings
    assert not frames[-1].warnings
    # The secret never leaks, and the redaction is counted exactly once.
    assert "leaked@example.com" not in repr([f.facts for f in frames])
    assert kernel.stats.redaction_events == 1
