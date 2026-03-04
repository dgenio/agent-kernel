"""Tests for InMemoryDriver and HTTPDriver."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_kernel import DriverError, InMemoryDriver
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.drivers.http import HTTPDriver, HTTPEndpoint

# ── InMemoryDriver ─────────────────────────────────────────────────────────────


def test_inmemory_register_and_execute() -> None:
    driver = InMemoryDriver()

    def handler(ctx: ExecutionContext) -> dict[str, Any]:
        return {"result": "ok", "args": ctx.args}

    driver.register_handler("my_op", handler)
    assert driver.driver_id == "memory"


@pytest.mark.asyncio
async def test_inmemory_execute_success() -> None:
    driver = InMemoryDriver()
    driver.register_handler("op1", lambda ctx: {"x": 1})
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1", args={"operation": "op1"})
    result = await driver.execute(ctx)
    assert result.data == {"x": 1}
    assert result.capability_id == "cap.x"


@pytest.mark.asyncio
async def test_inmemory_execute_fallback_to_capability_id() -> None:
    driver = InMemoryDriver()
    driver.register_handler("cap.x", lambda ctx: "direct")
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1")
    result = await driver.execute(ctx)
    assert result.data == "direct"


@pytest.mark.asyncio
async def test_inmemory_execute_unknown_operation_raises() -> None:
    driver = InMemoryDriver()
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1", args={"operation": "noop"})
    with pytest.raises(DriverError, match="no handler"):
        await driver.execute(ctx)


@pytest.mark.asyncio
async def test_inmemory_handler_exception_raises_driver_error() -> None:
    driver = InMemoryDriver()

    def bad_handler(ctx: ExecutionContext) -> None:
        raise RuntimeError("boom")

    driver.register_handler("bad_op", bad_handler)
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1", args={"operation": "bad_op"})
    with pytest.raises(DriverError, match="boom"):
        await driver.execute(ctx)


@pytest.mark.asyncio
async def test_billing_driver_list(billing_driver: InMemoryDriver) -> None:
    ctx = ExecutionContext(
        capability_id="billing.list_invoices",
        principal_id="u1",
        args={"operation": "list_invoices"},
    )
    result = await billing_driver.execute(ctx)
    assert isinstance(result.data, list)
    assert len(result.data) == 200


@pytest.mark.asyncio
async def test_billing_driver_list_filtered(billing_driver: InMemoryDriver) -> None:
    ctx = ExecutionContext(
        capability_id="billing.list_invoices",
        principal_id="u1",
        args={"operation": "list_invoices", "status": "paid"},
    )
    result = await billing_driver.execute(ctx)
    assert all(r["status"] == "paid" for r in result.data)


@pytest.mark.asyncio
async def test_billing_driver_get(billing_driver: InMemoryDriver) -> None:
    ctx = ExecutionContext(
        capability_id="billing.get_invoice",
        principal_id="u1",
        args={"operation": "get_invoice", "id": "INV-0001"},
    )
    result = await billing_driver.execute(ctx)
    assert result.data is not None
    assert result.data["id"] == "INV-0001"


@pytest.mark.asyncio
async def test_billing_driver_summarize(billing_driver: InMemoryDriver) -> None:
    ctx = ExecutionContext(
        capability_id="billing.summarize_spend",
        principal_id="u1",
        args={"operation": "summarize_spend"},
    )
    result = await billing_driver.execute(ctx)
    assert "totals" in result.data
    assert "invoice_count" in result.data
    assert result.data["invoice_count"] == 200


# ── HTTPDriver ─────────────────────────────────────────────────────────────────


def test_httpdriver_register_endpoint() -> None:
    driver = HTTPDriver(driver_id="myhttp")
    endpoint = HTTPEndpoint(url="http://example.com/api", method="GET")
    driver.register_endpoint("op1", endpoint)
    assert driver.driver_id == "myhttp"


@pytest.mark.asyncio
async def test_httpdriver_execute_get(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/test", method="GET")
    driver.register_endpoint("get_data", endpoint)

    mock_response = MagicMock()
    mock_response.json.return_value = [{"id": 1}]
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "get_data"},
        )
        result = await driver.execute(ctx)
    assert result.data == [{"id": 1}]


@pytest.mark.asyncio
async def test_httpdriver_unknown_operation_raises() -> None:
    driver = HTTPDriver()
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1", args={"operation": "noop"})
    with pytest.raises(DriverError, match="no endpoint"):
        await driver.execute(ctx)


@pytest.mark.asyncio
async def test_httpdriver_http_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/fail", method="GET")
    driver.register_endpoint("fail_op", endpoint)

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    error = httpx.HTTPStatusError("Server Error", request=MagicMock(), response=mock_response)
    mock_client.get = AsyncMock(side_effect=error)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "fail_op"},
        )
        with pytest.raises(DriverError, match="HTTP 500"):
            await driver.execute(ctx)
