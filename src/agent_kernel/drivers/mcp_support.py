"""Internal helpers for MCP transport wiring and result normalization."""

from __future__ import annotations

import importlib
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any

from ..errors import DriverError

SessionFactory = Callable[[], AbstractAsyncContextManager[Any]]


@dataclass(slots=True)
class ToolSpec:
    """Normalized MCP tool metadata for capability conversion."""

    name: str
    description: str


async def call_tool(session: Any, *, operation: str, params: dict[str, Any]) -> Any:
    """Call an MCP tool via tools/call."""
    return await session.call_tool(operation, arguments=params)


def extract_tool_specs(tool_list_response: Any) -> list[ToolSpec]:
    """Extract tool metadata from a tools/list response payload."""
    tools = getattr(tool_list_response, "tools", [])
    if not isinstance(tools, list):
        return []
    specs: list[ToolSpec] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not isinstance(name, str) or not name:
            continue
        specs.append(
            ToolSpec(
                name=name,
                description=str(getattr(tool, "description", "") or ""),
            )
        )
    return specs


def normalize_call_result(result: Any, *, operation: str, driver_id: str) -> Any:
    """Normalize an MCP CallToolResult into plain Python data."""
    is_error = bool(getattr(result, "isError", False))
    content = [_normalize_content_item(c) for c in (getattr(result, "content", None) or [])]

    if is_error:
        detail = next(
            (b["text"] for b in content if b.get("type") == "text" and b.get("text", "").strip()),
            "MCP server returned isError=true",
        )
        raise DriverError(
            f"MCPDriver '{driver_id}' tool '{operation}' returned an error: {detail}"
        )

    structured: dict[str, Any] | None = getattr(result, "structuredContent", None)
    if structured is not None and content:
        return {"structured_content": structured, "content": content}
    if structured is not None:
        return structured
    return content


def import_optional(module_name: str) -> Any:
    """Import optional MCP SDK module with a consistent guidance message."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise ImportError(
            "MCP support requires the optional dependency 'mcp>=1.0'. "
            "Install it with: pip install 'weaver-kernel[mcp]'"
        ) from exc


def build_stdio_session_factory(*, command: str, args: list[str]) -> SessionFactory:
    """Build a stdio-backed MCP session factory."""
    stdio_mod = import_optional("mcp.client.stdio")
    session_mod = import_optional("mcp.client.session")

    stdio_client = stdio_mod.stdio_client
    server_params_cls = stdio_mod.StdioServerParameters
    session_cls = session_mod.ClientSession

    @asynccontextmanager
    async def factory() -> AsyncIterator[Any]:
        params = server_params_cls(command=command, args=args)
        async with stdio_client(params) as streams:
            read_stream, write_stream = streams
            async with session_cls(read_stream, write_stream) as session:
                await session.initialize()
                yield session

    return factory


def build_http_session_factory(*, url: str) -> SessionFactory:
    """Build a Streamable HTTP-backed MCP session factory."""
    streamable_mod = import_optional("mcp.client.streamable_http")
    session_mod = import_optional("mcp.client.session")

    streamable_http_client = streamable_mod.streamable_http_client
    session_cls = session_mod.ClientSession

    @asynccontextmanager
    async def factory() -> AsyncIterator[Any]:
        async with streamable_http_client(url) as streams:
            read_stream, write_stream = streams
            async with session_cls(read_stream, write_stream) as session:
                await session.initialize()
                yield session

    return factory


def _normalize_content_item(item: Any) -> dict[str, Any]:
    item_type = str(getattr(item, "type", "")).lower()
    if item_type == "text":
        return {"type": "text", "text": str(getattr(item, "text", ""))}
    if item_type == "image":
        return {
            "type": "image",
            "data": getattr(item, "data", None),
            "mime_type": getattr(item, "mimeType", None),
        }
    if item_type in {"resource", "resourcelink"}:
        resource = getattr(item, "resource", item)
        return {
            "type": "resource",
            "resource": resource.model_dump() if hasattr(resource, "model_dump") else resource,
        }
    # AudioContent or any future type - fall back to model_dump
    return item.model_dump() if hasattr(item, "model_dump") else {"type": "value", "value": item}
