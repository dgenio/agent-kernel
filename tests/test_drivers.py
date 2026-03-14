"""Tests for InMemoryDriver and HTTPDriver."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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


@pytest.mark.asyncio
async def test_httpdriver_execute_post() -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/items", method="POST")
    driver.register_endpoint("create_item", endpoint)

    mock_response = MagicMock()
    mock_response.json.return_value = {"created": True}
    mock_response.status_code = 201
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "create_item", "name": "test"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"created": True}
    mock_client.post.assert_called_once()


@pytest.mark.asyncio
async def test_httpdriver_execute_put() -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/items/1", method="PUT")
    driver.register_endpoint("update_item", endpoint)

    mock_response = MagicMock()
    mock_response.json.return_value = {"updated": True}
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.put = AsyncMock(return_value=mock_response)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "update_item", "name": "updated"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"updated": True}
    mock_client.put.assert_called_once()


@pytest.mark.asyncio
async def test_httpdriver_execute_delete() -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/items/1", method="DELETE")
    driver.register_endpoint("delete_item", endpoint)

    mock_response = MagicMock()
    mock_response.json.return_value = {"deleted": True}
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.delete = AsyncMock(return_value=mock_response)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "delete_item"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"deleted": True}
    mock_client.delete.assert_called_once()


@pytest.mark.asyncio
async def test_httpdriver_execute_patch_uses_request() -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/items/1", method="PATCH")
    driver.register_endpoint("patch_item", endpoint)

    mock_response = MagicMock()
    mock_response.json.return_value = {"patched": True}
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_response)

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "patch_item", "field": "value"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"patched": True}
    mock_client.request.assert_called_once_with(
        "PATCH", "http://localhost:9999/items/1", json={"field": "value"}
    )


@pytest.mark.asyncio
async def test_httpdriver_request_error_raises() -> None:
    driver = HTTPDriver()
    endpoint = HTTPEndpoint(url="http://localhost:9999/unreachable", method="GET")
    driver.register_endpoint("unreachable_op", endpoint)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(
        side_effect=httpx.ConnectError("Connection refused", request=MagicMock())
    )

    with patch("agent_kernel.drivers.http.httpx.AsyncClient", return_value=mock_client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "unreachable_op"},
        )
        with pytest.raises(DriverError, match="Request to .* failed"):
            await driver.execute(ctx)
