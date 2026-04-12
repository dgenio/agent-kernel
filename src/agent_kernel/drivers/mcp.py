"""MCP driver: execute capabilities against Model Context Protocol servers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..enums import SafetyClass
from ..errors import DriverError
from ..models import Capability, ImplementationRef, RawResult
from .base import ExecutionContext
from .mcp_support import (
    SessionFactory,
    build_http_session_factory,
    build_stdio_session_factory,
    call_tool,
    extract_tool_specs,
    normalize_call_result,
)


class MCPDriver:
    """A driver that invokes capabilities via MCP tools/call."""

    def __init__(
        self,
        *,
        driver_id: str,
        session_factory: SessionFactory,
        server_name: str,
        transport: str,
        max_http_retries: int = 1,
    ) -> None:
        self._driver_id = driver_id
        self._session_factory = session_factory
        self._server_name = server_name
        self._transport = transport
        self._max_http_retries = max(max_http_retries, 0)

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver instance."""
        return self._driver_id

    @classmethod
    def from_stdio(
        cls,
        command: str,
        args: list[str] | None = None,
        *,
        server_name: str = "stdio",
    ) -> MCPDriver:
        """Create an MCP driver using stdio transport.

        Raises:
            ImportError: If the optional ``mcp`` dependency is not installed.
        """
        session_factory = build_stdio_session_factory(command=command, args=args or [])
        return cls(
            driver_id=f"mcp:{server_name}",
            session_factory=session_factory,
            server_name=server_name,
            transport="stdio",
            max_http_retries=0,
        )

    @classmethod
    def from_http(
        cls,
        url: str,
        *,
        server_name: str = "http",
        max_retries: int = 1,
    ) -> MCPDriver:
        """Create an MCP driver using Streamable HTTP transport.

        Raises:
            ImportError: If the optional ``mcp`` dependency is not installed.
        """
        session_factory = build_http_session_factory(url=url)
        return cls(
            driver_id=f"mcp:{server_name}",
            session_factory=session_factory,
            server_name=server_name,
            transport="http",
            max_http_retries=max_retries,
        )

    async def discover(
        self,
        *,
        namespace: str | None = None,
        safety_class_map: dict[str, SafetyClass] | None = None,
    ) -> list[Capability]:
        """Discover MCP tools and convert them to capabilities."""
        tool_list = await self._run_with_retry(
            operation_name="tools/list",
            action=lambda session: session.list_tools(),
        )

        capabilities: list[Capability] = []
        for spec in extract_tool_specs(tool_list):
            capability_id = f"{namespace}.{spec.name}" if namespace else spec.name
            safety_class = (
                safety_class_map.get(spec.name, SafetyClass.READ)
                if safety_class_map is not None
                else SafetyClass.READ
            )
            capabilities.append(
                Capability(
                    capability_id=capability_id,
                    name=spec.name,
                    description=spec.description,
                    safety_class=safety_class,
                    tags=["mcp", self._server_name],
                    impl=ImplementationRef(
                        driver_id=self._driver_id,
                        operation=spec.name,
                    ),
                )
            )
        return capabilities

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute an MCP tool call for the given capability context."""
        operation = str(ctx.args.get("operation", ctx.capability_id))
        params = {k: v for k, v in ctx.args.items() if k != "operation"}

        # Apply policy constraints as default arguments, without overriding explicit args.
        for key, value in ctx.constraints.items():
            params.setdefault(key, value)

        result = await self._run_with_retry(
            operation_name=f"tools/call:{operation}",
            action=lambda session: call_tool(
                session,
                operation=operation,
                params=params,
            ),
        )

        data = normalize_call_result(
            result,
            operation=operation,
            driver_id=self._driver_id,
        )
        return RawResult(
            capability_id=ctx.capability_id,
            data=data,
            metadata={
                "driver_id": self._driver_id,
                "transport": self._transport,
                "operation": operation,
            },
        )

    async def _run_with_retry(
        self,
        *,
        operation_name: str,
        action: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        attempts = 1 + self._max_http_retries if self._transport == "http" else 1
        last_exc: Exception | None = None

        for _attempt in range(attempts):
            try:
                async with self._session_factory() as session:
                    return await action(session)
            except DriverError:
                raise
            except Exception as exc:
                # Broad catch is intentional: exceptions at this level are
                # session/transport failures (connection refused, EOF, timeout).
                # MCP tool-level application errors are returned as isError=True
                # responses and converted to DriverError before reaching this
                # handler — they never appear as Python exceptions here.
                last_exc = exc

        reason = str(last_exc) if last_exc is not None else "unknown transport failure"
        raise DriverError(
            f"MCPDriver '{self._driver_id}' failed during {operation_name} over "
            f"{self._transport}: {reason}"
        ) from last_exc
