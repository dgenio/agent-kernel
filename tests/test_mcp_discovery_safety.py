"""Security-focused MCP discovery classification tests (#181)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from weaver_kernel import DriverError, MCPDriver, SafetyClass


class _Session:
    def __init__(self, tools: list[Any]) -> None:
        self._tools = tools

    async def list_tools(self, cursor: str | None = None) -> Any:
        return SimpleNamespace(tools=self._tools, nextCursor=None)


def _factory(tools: list[Any]) -> Any:
    @asynccontextmanager
    async def factory() -> AsyncIterator[_Session]:
        yield _Session(tools)

    return factory


def _tool(
    name: str,
    *,
    read_only: bool = False,
    destructive: bool = False,
) -> Any:
    annotations = None
    if read_only or destructive:
        annotations = SimpleNamespace(
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=False,
        )
    return SimpleNamespace(
        name=name,
        description=f"{name} tool",
        annotations=annotations,
        outputSchema=None,
    )


def _driver(*tools: Any) -> MCPDriver:
    return MCPDriver(
        driver_id="mcp:test",
        session_factory=_factory(list(tools)),
        server_name="test",
        transport="stdio",
    )


@pytest.mark.asyncio
async def test_unannotated_tools_are_rejected_by_default() -> None:
    driver = _driver(_tool("list_files"), _tool("delete_repo"))

    with pytest.raises(DriverError) as exc_info:
        await driver.discover(namespace="repo")

    message = str(exc_info.value)
    assert "delete_repo" in message
    assert "list_files" in message
    assert "missing metadata is not treated as READ authority" in message


@pytest.mark.asyncio
async def test_explicit_safety_map_classifies_unannotated_tool() -> None:
    driver = _driver(_tool("list_files"))

    capabilities = await driver.discover(
        namespace="repo",
        safety_class_map={"list_files": SafetyClass.READ},
    )

    assert len(capabilities) == 1
    assert capabilities[0].capability_id == "repo.list_files"
    assert capabilities[0].safety_class is SafetyClass.READ


@pytest.mark.asyncio
async def test_malformed_explicit_safety_map_fails_closed() -> None:
    driver = _driver(_tool("delete_repo"))

    with pytest.raises(DriverError, match=r"safety_class_map\['delete_repo'\]"):
        await driver.discover(
            safety_class_map={"delete_repo": "READ"},  # type: ignore[dict-item]
        )


@pytest.mark.asyncio
async def test_explicit_unannotated_fallback_warns_and_names_tools(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = _driver(_tool("send_email"), _tool("write_file"))

    with caplog.at_level(logging.WARNING, logger="weaver_kernel.drivers.mcp"):
        capabilities = await driver.discover(unannotated_safety=SafetyClass.WRITE)

    assert {cap.safety_class for cap in capabilities} == {SafetyClass.WRITE}
    assert "mcp_unannotated_safety_fallback" in caplog.text
    assert "send_email" in caplog.text
    assert "write_file" in caplog.text


@pytest.mark.asyncio
async def test_explicit_mcp_hints_still_infer_safety_class() -> None:
    driver = _driver(
        _tool("list_files", read_only=True),
        _tool("delete_repo", destructive=True),
    )

    capabilities = await driver.discover()
    by_name = {cap.name: cap.safety_class for cap in capabilities}

    assert by_name == {
        "list_files": SafetyClass.READ,
        "delete_repo": SafetyClass.DESTRUCTIVE,
    }


@pytest.mark.asyncio
async def test_invalid_unannotated_safety_is_rejected() -> None:
    driver = _driver(_tool("list_files"))

    with pytest.raises(DriverError, match="unannotated_safety"):
        await driver.discover(unannotated_safety="READ")  # type: ignore[arg-type]
