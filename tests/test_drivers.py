"""Tests for InMemoryDriver and HTTPDriver."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from weaver_kernel import DriverError, InMemoryDriver
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.drivers.http import HTTPDriver, HTTPEndpoint

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


def _mock_http_client(
    *,
    body: bytes = b"{}",
    status_code: int = 200,
    is_error: bool = False,
    headers: dict[str, str] | None = None,
    request_error: Exception | None = None,
) -> MagicMock:
    """Build a mock ``httpx.AsyncClient`` whose ``.stream()`` yields a response.

    Mirrors the streaming contract :class:`HTTPDriver` now relies on: an async
    context manager whose response exposes ``is_error``, ``aiter_bytes()``,
    ``aread()``, ``status_code``, ``headers``, and ``text``.
    """
    response = MagicMock()
    response.status_code = status_code
    response.is_error = is_error
    response.headers = headers or {"content-type": "application/json"}
    response.text = body.decode("utf-8", "replace")
    response.aread = AsyncMock(return_value=body)

    async def _aiter_bytes() -> Any:
        # Emit small chunks so the size guard is exercised across boundaries.
        for i in range(0, len(body), 8):
            yield body[i : i + 8]

    response.aiter_bytes = _aiter_bytes

    stream_cm = MagicMock()
    stream_cm.__aenter__ = AsyncMock(return_value=response)
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    client = MagicMock()
    if request_error is not None:
        client.stream = MagicMock(side_effect=request_error)
    else:
        client.stream = MagicMock(return_value=stream_cm)
    client.aclose = AsyncMock()
    return client


def test_httpdriver_register_endpoint() -> None:
    driver = HTTPDriver(driver_id="myhttp")
    endpoint = HTTPEndpoint(url="http://example.com/api", method="GET")
    driver.register_endpoint("op1", endpoint)
    assert driver.driver_id == "myhttp"


@pytest.mark.asyncio
async def test_httpdriver_execute_get() -> None:
    driver = HTTPDriver()
    driver.register_endpoint("get_data", HTTPEndpoint(url="http://localhost:9999/test"))
    client = _mock_http_client(body=b'[{"id": 1}]')

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_data"}
        )
        result = await driver.execute(ctx)
    assert result.data == [{"id": 1}]
    assert result.metadata == {"status_code": 200, "url": "http://localhost:9999/test"}
    assert client.stream.call_args.args[0] == "GET"


@pytest.mark.asyncio
async def test_httpdriver_reuses_pooled_client() -> None:
    """The client is built once and reused across invocations (#194)."""
    driver = HTTPDriver()
    driver.register_endpoint("get_data", HTTPEndpoint(url="http://localhost:9999/test"))
    client = _mock_http_client(body=b"{}")

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client) as ctor:
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_data"}
        )
        await driver.execute(ctx)
        await driver.execute(ctx)
    assert ctor.call_count == 1
    assert client.stream.call_count == 2


@pytest.mark.asyncio
async def test_httpdriver_aclose_closes_client() -> None:
    """aclose() releases the pooled client and is safe to call twice (#194)."""
    driver = HTTPDriver()
    driver.register_endpoint("get_data", HTTPEndpoint(url="http://localhost:9999/test"))
    client = _mock_http_client(body=b"{}")

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_data"}
        )
        await driver.execute(ctx)
        await driver.aclose()
        await driver.aclose()  # idempotent
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_httpdriver_unknown_operation_raises() -> None:
    driver = HTTPDriver()
    ctx = ExecutionContext(capability_id="cap.x", principal_id="u1", args={"operation": "noop"})
    with pytest.raises(DriverError, match="no endpoint"):
        await driver.execute(ctx)


@pytest.mark.asyncio
async def test_httpdriver_http_error_raises() -> None:
    driver = HTTPDriver()
    driver.register_endpoint("fail_op", HTTPEndpoint(url="http://localhost:9999/fail"))
    client = _mock_http_client(body=b"Internal Server Error", status_code=500, is_error=True)

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "fail_op"}
        )
        with pytest.raises(DriverError, match="HTTP 500"):
            await driver.execute(ctx)


@pytest.mark.asyncio
async def test_httpdriver_error_body_is_bounded() -> None:
    """An oversized error body is not buffered in full; the message is bounded (#194)."""
    driver = HTTPDriver(max_response_bytes=10)
    driver.register_endpoint("fail_big", HTTPEndpoint(url="http://localhost:9999/fail"))
    client = _mock_http_client(body=b"E" * 100_000, status_code=500, is_error=True)

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "fail_big"}
        )
        with pytest.raises(DriverError, match="HTTP 500") as excinfo:
            await driver.execute(ctx)
    # Only a bounded snippet is surfaced, regardless of the 100 KB body.
    assert len(str(excinfo.value)) < 300


@pytest.mark.asyncio
async def test_httpdriver_non_json_response_raises() -> None:
    """A 200 with a non-JSON body surfaces as a typed DriverError (#197)."""
    driver = HTTPDriver()
    driver.register_endpoint("get_html", HTTPEndpoint(url="http://localhost:9999/page"))
    client = _mock_http_client(
        body=b"<html>not json</html>", headers={"content-type": "text/html"}
    )

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_html"}
        )
        with pytest.raises(DriverError, match=r"non-JSON response.*content-type: text/html"):
            await driver.execute(ctx)


@pytest.mark.asyncio
async def test_httpdriver_text_response_format_returns_string() -> None:
    """A ``text`` endpoint returns the decoded body verbatim, no JSON parse (#197)."""
    driver = HTTPDriver()
    driver.register_endpoint(
        "get_text",
        HTTPEndpoint(url="http://localhost:9999/page", response_format="text"),
    )
    client = _mock_http_client(body=b"plain text body", headers={"content-type": "text/plain"})

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_text"}
        )
        result = await driver.execute(ctx)
    assert result.data == "plain text body"


@pytest.mark.asyncio
async def test_httpdriver_empty_body_returns_none() -> None:
    driver = HTTPDriver()
    driver.register_endpoint("get_empty", HTTPEndpoint(url="http://localhost:9999/empty"))
    client = _mock_http_client(body=b"")

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_empty"}
        )
        result = await driver.execute(ctx)
    assert result.data is None


@pytest.mark.asyncio
async def test_httpdriver_response_size_limit_aborts() -> None:
    """A body larger than ``max_response_bytes`` aborts with a DriverError (#194)."""
    driver = HTTPDriver(max_response_bytes=10)
    driver.register_endpoint("get_big", HTTPEndpoint(url="http://localhost:9999/big"))
    client = _mock_http_client(body=b"x" * 100)

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_big"}
        )
        with pytest.raises(DriverError, match=r"exceeded max_response_bytes \(10\)"):
            await driver.execute(ctx)


@pytest.mark.asyncio
async def test_httpdriver_response_size_limit_allows_small_body() -> None:
    """A body within ``max_response_bytes`` is returned normally (#194)."""
    driver = HTTPDriver(max_response_bytes=1000)
    driver.register_endpoint("get_small", HTTPEndpoint(url="http://localhost:9999/small"))
    client = _mock_http_client(body=b'{"ok": true}')

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "get_small"}
        )
        result = await driver.execute(ctx)
    assert result.data == {"ok": True}


@pytest.mark.asyncio
async def test_httpdriver_execute_post_sends_json_body() -> None:
    driver = HTTPDriver()
    driver.register_endpoint(
        "create_item", HTTPEndpoint(url="http://localhost:9999/items", method="POST")
    )
    client = _mock_http_client(body=b'{"created": true}', status_code=201)

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "create_item", "name": "test"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"created": True}
    assert client.stream.call_args.args[0] == "POST"
    assert client.stream.call_args.kwargs["json"] == {"name": "test"}


@pytest.mark.asyncio
async def test_httpdriver_execute_delete_sends_params() -> None:
    driver = HTTPDriver()
    driver.register_endpoint(
        "delete_item", HTTPEndpoint(url="http://localhost:9999/items/1", method="DELETE")
    )
    client = _mock_http_client(body=b'{"deleted": true}')

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "delete_item", "id": "1"}
        )
        result = await driver.execute(ctx)
    assert result.data == {"deleted": True}
    assert client.stream.call_args.args[0] == "DELETE"
    assert client.stream.call_args.kwargs["params"] == {"id": "1"}


@pytest.mark.asyncio
async def test_httpdriver_execute_patch_uses_method() -> None:
    driver = HTTPDriver()
    driver.register_endpoint(
        "patch_item", HTTPEndpoint(url="http://localhost:9999/items/1", method="PATCH")
    )
    client = _mock_http_client(body=b'{"patched": true}')

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x",
            principal_id="u1",
            args={"operation": "patch_item", "field": "value"},
        )
        result = await driver.execute(ctx)
    assert result.data == {"patched": True}
    assert client.stream.call_args.args[0] == "PATCH"
    assert client.stream.call_args.kwargs["json"] == {"field": "value"}


@pytest.mark.asyncio
async def test_httpdriver_request_error_raises() -> None:
    driver = HTTPDriver()
    driver.register_endpoint(
        "unreachable_op", HTTPEndpoint(url="http://localhost:9999/unreachable")
    )
    client = _mock_http_client(
        request_error=httpx.ConnectError("Connection refused", request=MagicMock())
    )

    with patch("weaver_kernel.drivers.http.httpx.AsyncClient", return_value=client):
        ctx = ExecutionContext(
            capability_id="cap.x", principal_id="u1", args={"operation": "unreachable_op"}
        )
        with pytest.raises(DriverError, match="Request to .* failed"):
            await driver.execute(ctx)
