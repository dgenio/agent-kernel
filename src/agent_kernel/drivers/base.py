"""Base driver protocol and execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

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
