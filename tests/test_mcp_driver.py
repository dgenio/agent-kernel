"""Tests for the built-in MCPDriver."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch

import pytest
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from agent_kernel import (
    CapabilityRegistry,
    CapabilityRequest,
    DriverError,
    Kernel,
    MCPDriver,
    Principal,
    SafetyClass,
    StaticRouter,
)


class _FakeSession:
    """Small async session stub for MCPDriver tests."""

    def __init__(
        self,
        *,
        tools: list[Tool] | None = None,
        call_result: CallToolResult | None = None,
        call_error: Exception | None = None,
    ) -> None:
        self._tools = tools or []
        self._call_result = call_result or CallToolResult(content=[])
        self._call_error = call_error
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self, cursor: str | None = None) -> ListToolsResult:
        return ListToolsResult(tools=self._tools)

    async def call_tool(
        self,
        operation: str,
        arguments: dict[str, Any],
        read_timeout_seconds: Any = None,
    ) -> CallToolResult:
        self.calls.append((operation, arguments))
        if self._call_error is not None:
            raise self._call_error
        return self._call_result


def _reusable_factory(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _factory() -> AsyncIterator[_FakeSession]:
        yield session

    return _factory


def _sequence_factory(sessions: list[_FakeSession]) -> Any:
    @asynccontextmanager
    async def _factory() -> AsyncIterator[_FakeSession]:
        if not sessions:
            raise RuntimeError("no fake sessions left")
        yield sessions.pop(0)

    return _factory


def test_from_stdio_missing_dependency_raises_helpful_import_error() -> None:
    with patch("agent_kernel.drivers.mcp_support.importlib.import_module") as import_module:
        import_module.side_effect = ModuleNotFoundError("No module named 'mcp'")
        with pytest.raises(ImportError, match=r"weaver-kernel\[mcp\]"):
            MCPDriver.from_stdio("python", ["server.py"])


def test_from_http_missing_dependency_raises_helpful_import_error() -> None:
    with patch("agent_kernel.drivers.mcp_support.importlib.import_module") as import_module:
        import_module.side_effect = ModuleNotFoundError("No module named 'mcp'")
        with pytest.raises(ImportError, match=r"weaver-kernel\[mcp\]"):
            MCPDriver.from_http("http://localhost:8080/mcp")


@pytest.mark.asyncio
async def test_discover_converts_tools_to_capabilities() -> None:
    session = _FakeSession(
        tools=[
            Tool(name="list_files", description="List files", inputSchema={}),
            Tool(name="write_file", description="Write file", inputSchema={}),
        ]
    )
    driver = MCPDriver(
        driver_id="mcp:local",
        session_factory=_reusable_factory(session),
        server_name="local",
        transport="stdio",
    )

    capabilities = await driver.discover(
        namespace="fs", safety_class_map={"write_file": SafetyClass.WRITE}
    )

    assert [cap.capability_id for cap in capabilities] == [
        "fs.list_files",
        "fs.write_file",
    ]
    assert capabilities[0].safety_class == SafetyClass.READ
    assert capabilities[1].safety_class == SafetyClass.WRITE
    assert capabilities[0].impl is not None
    assert capabilities[0].impl.driver_id == "mcp:local"
    assert capabilities[0].impl.operation == "list_files"


@pytest.mark.asyncio
async def test_execute_calls_tool_and_applies_constraints_defaults() -> None:
    session = _FakeSession(
        call_result=CallToolResult(content=[TextContent(type="text", text="ok")])
    )
    driver = MCPDriver(
        driver_id="mcp:local",
        session_factory=_reusable_factory(session),
        server_name="local",
        transport="stdio",
    )

    from agent_kernel.drivers.base import ExecutionContext

    ctx = ExecutionContext(
        capability_id="fs.list_files",
        principal_id="u1",
        args={"operation": "list_files", "path": "/tmp", "max_rows": 5},
        constraints={"max_rows": 2, "allowed_fields": ["name"]},
    )

    result = await driver.execute(ctx)

    assert result.capability_id == "fs.list_files"
    assert result.data == [{"type": "text", "text": "ok"}]
    assert session.calls[0][0] == "list_files"
    # Explicit args are preserved; missing constraints are merged in.
    assert session.calls[0][1]["max_rows"] == 5
    assert session.calls[0][1]["allowed_fields"] == ["name"]


@pytest.mark.asyncio
async def test_execute_prefers_structured_content_when_available() -> None:
    session = _FakeSession(
        call_result=CallToolResult(
            structuredContent={"total": 3},
            content=[TextContent(type="text", text="computed")],
        )
    )
    driver = MCPDriver(
        driver_id="mcp:local",
        session_factory=_reusable_factory(session),
        server_name="local",
        transport="stdio",
    )

    from agent_kernel.drivers.base import ExecutionContext

    ctx = ExecutionContext(capability_id="math.sum", principal_id="u1")
    result = await driver.execute(ctx)

    assert result.data == {
        "structured_content": {"total": 3},
        "content": [{"type": "text", "text": "computed"}],
    }


@pytest.mark.asyncio
async def test_execute_raises_driver_error_on_mcp_is_error() -> None:
    session = _FakeSession(
        call_result=CallToolResult(
            isError=True,
            content=[TextContent(type="text", text="permission denied")],
        )
    )
    driver = MCPDriver(
        driver_id="mcp:local",
        session_factory=_reusable_factory(session),
        server_name="local",
        transport="stdio",
    )

    from agent_kernel.drivers.base import ExecutionContext

    ctx = ExecutionContext(capability_id="secrets.read", principal_id="u1")
    with pytest.raises(DriverError, match="permission denied"):
        await driver.execute(ctx)


@pytest.mark.asyncio
async def test_http_transport_retries_after_connection_drop() -> None:
    first = _FakeSession(call_error=RuntimeError("connection dropped"))
    second = _FakeSession(
        call_result=CallToolResult(content=[TextContent(type="text", text="ok")])
    )

    driver = MCPDriver(
        driver_id="mcp:http",
        session_factory=_sequence_factory([first, second]),
        server_name="remote",
        transport="http",
        max_http_retries=1,
    )

    from agent_kernel.drivers.base import ExecutionContext

    ctx = ExecutionContext(capability_id="echo", principal_id="u1")
    result = await driver.execute(ctx)

    assert result.data == [{"type": "text", "text": "ok"}]
    assert len(first.calls) == 1
    assert len(second.calls) == 1


@pytest.mark.asyncio
async def test_kernel_pipeline_with_discover_register_grant_invoke() -> None:
    session = _FakeSession(
        tools=[Tool(name="math.sum", description="Sum two values", inputSchema={})],
        call_result=CallToolResult(structuredContent={"total": 3}, content=[]),
    )
    driver = MCPDriver(
        driver_id="mcp:demo",
        session_factory=_reusable_factory(session),
        server_name="demo",
        transport="stdio",
    )

    capabilities = await driver.discover()
    registry = CapabilityRegistry()
    registry.register_many(capabilities)

    router = StaticRouter(routes={"math.sum": ["mcp:demo"]}, fallback=[])
    kernel = Kernel(registry=registry, router=router)
    kernel.register_driver(driver)

    principal = Principal(principal_id="u1", roles=["reader"])
    request = CapabilityRequest(capability_id="math.sum", goal="sum numbers")

    token = kernel.get_token(request, principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={"operation": "math.sum", "a": 1, "b": 2},
    )

    assert frame.response_mode == "summary"
    assert any("total" in fact.lower() for fact in frame.facts)


@pytest.mark.asyncio
async def test_real_fastmcp_in_process_discover_and_execute() -> None:
    """Full discover→execute cycle driven by a real FastMCP server in-process."""
    from mcp.client.session import ClientSession
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.memory import create_connected_server_and_client_session

    mcp_srv = FastMCP("math")

    @mcp_srv.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    @asynccontextmanager
    async def in_memory_factory() -> AsyncIterator[ClientSession]:
        async with create_connected_server_and_client_session(mcp_srv) as session:
            yield session

    driver = MCPDriver(
        driver_id="mcp:math",
        session_factory=in_memory_factory,
        server_name="math",
        transport="stdio",
    )

    capabilities = await driver.discover(namespace="math")
    assert any(cap.capability_id == "math.add" for cap in capabilities)
    add_cap = next(c for c in capabilities if c.capability_id == "math.add")
    assert add_cap.impl is not None
    assert add_cap.impl.operation == "add"

    from agent_kernel.drivers.base import ExecutionContext

    ctx = ExecutionContext(
        capability_id="math.add",
        principal_id="u1",
        args={"operation": "add", "a": 3, "b": 4},
    )
    result = await driver.execute(ctx)
    assert isinstance(result.data, dict)
    assert result.data["structured_content"]["result"] == 7
    assert result.data["content"][0]["text"] == "7"
