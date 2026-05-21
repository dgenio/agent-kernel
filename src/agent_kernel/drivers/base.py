"""Base driver protocol and execution context."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..models import RawResult


@dataclass(slots=True)
class ExecutionContext:
    """Runtime context passed to a driver when executing a capability."""

    capability_id: str
    principal_id: str
    args: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)
    action_id: str = ""


class Driver(Protocol):
    """Interface for capability execution drivers."""

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver instance."""
        ...

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute a capability and return a raw result.

        Args:
            ctx: Execution context including capability ID, args, and constraints.

        Returns:
            The unfiltered :class:`RawResult` from the underlying system.

        Raises:
            DriverError: If execution fails.
        """
        ...


@runtime_checkable
class StreamingDriver(Protocol):
    """Optional extension to :class:`Driver` for chunked output.

    Drivers that can produce results incrementally implement this
    protocol in addition to :class:`Driver`. :meth:`Kernel.invoke_stream`
    uses ``isinstance(driver, StreamingDriver)`` (runtime-checkable) to
    detect support and falls back to :meth:`Driver.execute` when a
    driver only implements the base protocol.

    Chunks are plain dictionaries; each is run through the firewall
    independently so PII redaction applies on a per-chunk basis. A
    chunk may carry the synthetic key ``"__is_final__": True`` to mark
    the last chunk explicitly — otherwise consumers should treat the
    iterator's natural end as end-of-stream.
    """

    @property
    def driver_id(self) -> str:  # pragma: no cover - protocol stub
        ...

    async def execute(
        self, ctx: ExecutionContext
    ) -> RawResult:  # pragma: no cover - protocol stub
        ...

    def execute_stream(self, ctx: ExecutionContext) -> AsyncIterator[dict[str, Any]]:
        """Execute a capability and yield response chunks.

        Declared with ``def`` (not ``async def``) because async-generator
        implementations — the natural shape, using ``async def`` + ``yield``
        — return the async iterator *directly* when called. An
        ``async def`` Protocol signature would force callers to first
        ``await`` the result, breaking the async-generator idiom.

        Args:
            ctx: Execution context including capability ID, args, and constraints.

        Returns:
            An async iterator of dictionary payloads — one per chunk. A
            chunk may carry the synthetic key ``"__is_final__": True``
            to mark itself as the last one.

        Raises:
            DriverError: If execution fails (may be raised mid-stream).
        """
        ...
