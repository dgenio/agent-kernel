"""MCP driver: execute capabilities against Model Context Protocol servers."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal

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

logger = logging.getLogger(__name__)

UnannotatedSafety = SafetyClass | Literal["reject"]
"""How discovery handles a tool with no usable MCP safety annotation."""


def _load_mcp_error() -> type[BaseException] | None:
    """Return the ``McpError`` type, or ``None`` when ``mcp`` is unavailable.

    Imported via ``importlib`` (matching ``mcp_support.import_optional``) so the
    optional-dependency branch is testable. Resolving the type into a separate,
    explicitly annotated module global avoids the mypy ``[no-redef]`` that the
    old ``import ... as _McpError`` pattern produced when ``mcp`` was absent and
    the import resolved to ``Any`` under ``ignore_missing_imports``.
    """
    try:
        exceptions = importlib.import_module("mcp.shared.exceptions")
    except ImportError:
        return None
    # Guard attribute access too: if the module imports but ``McpError`` is
    # missing or renamed, degrade to ``None`` (matching the old
    # ``from ... import McpError`` ImportError fallback) rather than raising
    # AttributeError at import time and breaking the whole driver module.
    error_type = getattr(exceptions, "McpError", None)
    if isinstance(error_type, type) and issubclass(error_type, BaseException):
        return error_type
    return None


# Resolved once at import time and used in _run_with_retries to classify
# protocol-level rejections as non-retryable. None when the optional ``mcp``
# dependency is not installed (factory methods raise ImportError first, so this
# is never None on a live driver instance).
_McpError: type[BaseException] | None = _load_mcp_error()


def _infer_safety_class(spec: ToolSpec) -> SafetyClass | None:
    """Infer a ``SafetyClass`` only from explicit MCP ToolAnnotations hints.

    MCP annotations are advisory metadata, not an authorization statement. A
    destructive hint wins over a read-only hint. When neither useful hint is
    present, return ``None`` so the caller must reject or apply an explicitly
    configured fallback instead of silently treating the tool as READ.
    """
    if spec.destructive_hint:
        return SafetyClass.DESTRUCTIVE
    if spec.read_only_hint:
        return SafetyClass.READ
    return None


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
        unannotated_safety: UnannotatedSafety = "reject",
    ) -> list[Capability]:
        """Discover MCP tools and convert them to deliberately classified capabilities.

        Explicit ``safety_class_map`` entries take precedence over advisory MCP
        annotations. A tool with neither an explicit override nor a useful MCP
        safety hint is rejected by default. Callers that knowingly accept a
        fallback may pass a ``SafetyClass`` via ``unannotated_safety``; doing so
        emits a warning naming every tool that received that fallback.

        Args:
            namespace: Optional capability-id namespace.
            safety_class_map: Explicit per-tool classifications supplied by the
                operator. These are trusted configuration and override MCP hints.
            unannotated_safety: ``"reject"`` (default) or an explicit fallback
                ``SafetyClass`` for otherwise unclassified tools.

        Raises:
            DriverError: If ``unannotated_safety`` is invalid or one or more tools
                remain unclassified while the mode is ``"reject"``.
        """
        if unannotated_safety != "reject" and not isinstance(unannotated_safety, SafetyClass):
            raise DriverError(
                "unannotated_safety must be 'reject' or a SafetyClass, "
                f"got {unannotated_safety!r}."
            )

        tools = await self._run_with_retry(
            operation_name="tools/list",
            action=self._fetch_all_tools,
        )

        capabilities: list[Capability] = []
        rejected_tools: list[str] = []
        fallback_tools: list[str] = []

        for spec in extract_tool_specs(tools):
            capability_id = f"{namespace}.{spec.name}" if namespace else spec.name

            if safety_class_map is not None and spec.name in safety_class_map:
                safety_class = safety_class_map[spec.name]
            else:
                inferred = _infer_safety_class(spec)
                if inferred is not None:
                    safety_class = inferred
                elif unannotated_safety == "reject":
                    rejected_tools.append(spec.name)
                    continue
                else:
                    safety_class = unannotated_safety
                    fallback_tools.append(spec.name)

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

        if rejected_tools:
            names = ", ".join(sorted(rejected_tools))
            raise DriverError(
                f"MCPDriver '{self._driver_id}' refused to auto-register unclassified "
                f"tools: {names}. Classify them with safety_class_map or explicitly "
                "set unannotated_safety to a SafetyClass. MCP annotations are advisory "
                "and missing metadata is not treated as READ authority."
            )

        if fallback_tools:
            logger.warning(
                "mcp_unannotated_safety_fallback driver_id=%s safety_class=%s tools=%s",
                self._driver_id,
                unannotated_safety.value,
                ",".join(sorted(fallback_tools)),
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
