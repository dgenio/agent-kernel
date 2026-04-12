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
    ToolSpec,
    build_http_session_factory,
    build_stdio_session_factory,
    call_tool,
    extract_tool_specs,
    normalize_call_result,
)

# Lazy import of McpError — only available when the mcp optional dep is installed.
# If mcp is absent, factory methods raise ImportError before any session is created,
# so _McpError will never be None on a live driver instance.
try:
    from mcp.shared.exceptions import McpError as _McpError
except ImportError:  # pragma: no cover
    _McpError = None  # type: ignore[assignment,misc]


def _infer_safety_class(spec: ToolSpec) -> SafetyClass:
    """Infer a SafetyClass from MCP ToolAnnotations hints.

    Uses a conservative default of READ when annotations are absent.
    The caller's safety_class_map takes precedence over the inferred value.
    """
    if spec.destructive_hint:
        return SafetyClass.DESTRUCTIVE
    if spec.read_only_hint:
        return SafetyClass.READ
    return SafetyClass.READ


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
        """Discover MCP tools across all pages and convert them to capabilities."""
        tools = await self._run_with_retry(
            operation_name="tools/list",
            action=self._fetch_all_tools,
        )

        capabilities: list[Capability] = []
        for spec in extract_tool_specs(tools):
            capability_id = f"{namespace}.{spec.name}" if namespace else spec.name
            inferred = _infer_safety_class(spec)
            safety_class = (
                safety_class_map.get(spec.name, inferred)
                if safety_class_map is not None
                else inferred
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

    async def _fetch_all_tools(self, session: Any) -> list[Any]:
        """Paginate tools/list to exhaustion and return a flat list of Tool objects."""
        all_tools: list[Any] = []
        cursor: str | None = None
        while True:
            result = await session.list_tools(cursor=cursor)
            all_tools.extend(getattr(result, "tools", []) or [])
            cursor = getattr(result, "nextCursor", None)
            if not cursor:
                break
        return all_tools

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute an MCP tool call for the given capability context."""
        operation = str(ctx.args.get("operation", ctx.capability_id))
        params = {k: v for k, v in ctx.args.items() if k != "operation"}

        # Apply policy constraints as default arguments, without overriding explicit args.
        # read_timeout_seconds is an SDK control parameter — applied to the session call
        # directly rather than forwarded to the tool as an argument.
        read_timeout_seconds_raw = ctx.constraints.get("read_timeout_seconds")
        for key, value in ctx.constraints.items():
            if key != "read_timeout_seconds":
                params.setdefault(key, value)

        read_timeout_seconds: float | None = (
            float(read_timeout_seconds_raw) if read_timeout_seconds_raw is not None else None
        )

        result = await self._run_with_retry(
            operation_name=f"tools/call:{operation}",
            action=lambda session: call_tool(
                session,
                operation=operation,
                params=params,
                read_timeout_seconds=read_timeout_seconds,
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
                # McpError is a protocol-level rejection (tool not found, auth
                # failure, invalid params) — the server processed and rejected the
                # request. It is not retryable; surface it immediately as DriverError.
                if _McpError is not None and isinstance(exc, _McpError):
                    raise DriverError(
                        f"MCPDriver '{self._driver_id}' received a protocol error "
                        f"during {operation_name}: {exc}"
                    ) from exc
                # All other exceptions are session/transport failures (connection
                # refused, EOF, timeout) and are retryable for HTTP transport.
                # Note: HTTP retries create at-least-once delivery semantics for
                # tools/call. Callers using WRITE/DESTRUCTIVE capabilities over HTTP
                # should ensure the target tool is idempotent, or set max_retries=0.
                last_exc = exc

        reason = str(last_exc) if last_exc is not None else "unknown transport failure"
        raise DriverError(
            f"MCPDriver '{self._driver_id}' failed during {operation_name} over "
            f"{self._transport}: {reason}"
        ) from last_exc
