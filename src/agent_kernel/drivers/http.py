"""HTTPDriver: execute capabilities against HTTP APIs using httpx."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from ..errors import DriverError
from ..models import RawResult
from .base import ExecutionContext


@dataclass
class HTTPEndpoint:
    """Describes an HTTP endpoint for a capability operation."""

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0


class HTTPDriver:
    """A driver that invokes capabilities via HTTP using :mod:`httpx`.

    Each operation must be registered with an :class:`HTTPEndpoint`.
    The driver performs *synchronous* execution inside an async method by
    using ``httpx.AsyncClient`` for proper async support.
    """

    def __init__(
        self,
        driver_id: str = "http",
        *,
        base_headers: dict[str, str] | None = None,
        default_timeout: float = 30.0,
    ) -> None:
        self._driver_id = driver_id
        self._endpoints: dict[str, HTTPEndpoint] = {}
        self._base_headers = base_headers or {}
        self._default_timeout = default_timeout

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver."""
        return self._driver_id

    def register_endpoint(self, operation: str, endpoint: HTTPEndpoint) -> None:
        """Register an HTTP endpoint for an operation.

        Args:
            operation: The operation name to handle.
            endpoint: The :class:`HTTPEndpoint` configuration.
        """
        self._endpoints[operation] = endpoint

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute an HTTP request for the given context.

        The operation is resolved from ``ctx.args.get("operation")`` first,
        then falls back to ``ctx.capability_id``.

        Args:
            ctx: The execution context.

        Returns:
            :class:`RawResult` containing the parsed JSON response.

        Raises:
            DriverError: If the endpoint is not registered or the request fails.
        """
        operation = str(ctx.args.get("operation", ctx.capability_id))
        endpoint = self._endpoints.get(operation)
        if endpoint is None:
            raise DriverError(
                f"HTTPDriver '{self._driver_id}' has no endpoint for operation='{operation}'."
            )

        headers = {**self._base_headers, **endpoint.headers}
        params: dict[str, Any] = {}
        json_body: dict[str, Any] | None = None

        if endpoint.method.upper() == "GET":
            params = {k: v for k, v in ctx.args.items() if k != "operation"}
        else:
            json_body = {k: v for k, v in ctx.args.items() if k != "operation"}

        try:
            async with httpx.AsyncClient(headers=headers, timeout=endpoint.timeout) as client:
                if endpoint.method.upper() == "GET":
                    response = await client.get(endpoint.url, params=params)
                elif endpoint.method.upper() == "POST":
                    response = await client.post(endpoint.url, json=json_body)
                elif endpoint.method.upper() == "PUT":
                    response = await client.put(endpoint.url, json=json_body)
                elif endpoint.method.upper() == "DELETE":
                    response = await client.delete(endpoint.url, params=params)
                else:
                    response = await client.request(
                        endpoint.method.upper(), endpoint.url, json=json_body
                    )
                response.raise_for_status()
                data: Any = response.json()
        except httpx.HTTPStatusError as exc:
            raise DriverError(
                f"HTTPDriver '{self._driver_id}': HTTP {exc.response.status_code} "
                f"from {endpoint.url}: {exc.response.text[:200]}"
            ) from exc
        except httpx.RequestError as exc:
            raise DriverError(
                f"HTTPDriver '{self._driver_id}': Request to {endpoint.url} failed: {exc}"
            ) from exc

        return RawResult(
            capability_id=ctx.capability_id,
            data=data,
            metadata={"status_code": response.status_code, "url": endpoint.url},
        )
