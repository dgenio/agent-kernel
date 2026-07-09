"""HTTPDriver: execute capabilities against HTTP APIs using httpx."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from ..errors import DriverError
from ..models import RawResult
from .base import ExecutionContext

_DEFAULT_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)


@dataclass
class HTTPEndpoint:
    """Describes an HTTP endpoint for a capability operation."""

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float | None = None
    """Per-endpoint timeout in seconds. Falls back to the driver's ``default_timeout``."""
    response_format: Literal["json", "text"] = "json"
    """How to read a successful body: parse as JSON (default) or keep it as text."""


class HTTPDriver:
    """A driver that invokes capabilities via HTTP using :mod:`httpx`.

    Each operation must be registered with an :class:`HTTPEndpoint`. The driver
    holds a single long-lived :class:`httpx.AsyncClient` so requests reuse the
    connection pool and keep-alive instead of paying a fresh TLS handshake on
    every call (#194); call :meth:`aclose` on shutdown to release it. Bodies are
    size-bounded (``max_response_bytes``) and parsed defensively — a non-JSON
    body from a JSON endpoint raises :class:`DriverError` rather than leaking a
    raw decode error (#197).
    """

    def __init__(
        self,
        driver_id: str = "http",
        *,
        base_headers: dict[str, str] | None = None,
        default_timeout: float = 30.0,
        limits: httpx.Limits | None = None,
        max_response_bytes: int | None = None,
    ) -> None:
        self._driver_id = driver_id
        self._endpoints: dict[str, HTTPEndpoint] = {}
        self._base_headers = base_headers or {}
        self._default_timeout = default_timeout
        self._limits = limits or _DEFAULT_LIMITS
        self._max_response_bytes = max_response_bytes
        self._client: httpx.AsyncClient | None = None

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

    def _get_client(self) -> httpx.AsyncClient:
        """Return the shared client, creating it on first use.

        Built lazily so the connection pool, default headers, and limits are
        established once and reused across invocations (#194).
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers=self._base_headers,
                timeout=self._default_timeout,
                limits=self._limits,
            )
        return self._client

    async def aclose(self) -> None:
        """Close the shared client and release its connection pool.

        Idempotent — safe to call more than once. Callers that construct an
        :class:`HTTPDriver` own its lifecycle and should call this on shutdown
        (e.g. in a ``finally`` block or async-context teardown).
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute an HTTP request for the given context.

        The operation is resolved from ``ctx.args.get("operation")`` first,
        then falls back to ``ctx.capability_id``.

        Args:
            ctx: The execution context.

        Returns:
            :class:`RawResult` containing the parsed JSON response, or the raw
            text when the endpoint's ``response_format`` is ``"text"``.

        Raises:
            DriverError: If the endpoint is not registered, the request fails,
                the response exceeds ``max_response_bytes``, or a JSON endpoint
                returns a body that is not valid JSON.
        """
        operation = str(ctx.args.get("operation", ctx.capability_id))
        endpoint = self._endpoints.get(operation)
        if endpoint is None:
            raise DriverError(
                f"HTTPDriver '{self._driver_id}' has no endpoint for operation='{operation}'."
            )

        method = endpoint.method.upper()
        params: dict[str, Any] = {}
        json_body: dict[str, Any] | None = None
        if method in ("GET", "DELETE"):
            params = {k: v for k, v in ctx.args.items() if k != "operation"}
        else:
            json_body = {k: v for k, v in ctx.args.items() if k != "operation"}

        effective_timeout = (
            endpoint.timeout if endpoint.timeout is not None else self._default_timeout
        )
        client = self._get_client()

        try:
            async with client.stream(
                method,
                endpoint.url,
                params=params,
                json=json_body,
                headers=endpoint.headers,
                timeout=effective_timeout,
            ) as response:
                if response.is_error:
                    # Bound the error-body read too: an arbitrarily large error
                    # body must not be buffered just to build the message (#194).
                    snippet = await self._read_error_snippet(response)
                    raise DriverError(
                        f"HTTPDriver '{self._driver_id}': HTTP {response.status_code} "
                        f"from {endpoint.url}: {snippet}"
                    )
                body = await self._read_bounded(response, url=endpoint.url)
                status_code = response.status_code
                content_type = response.headers.get("content-type", "")
        except httpx.RequestError as exc:
            raise DriverError(
                f"HTTPDriver '{self._driver_id}': Request to {endpoint.url} failed: {exc}"
            ) from exc

        data = self._decode_body(
            body,
            response_format=endpoint.response_format,
            url=endpoint.url,
            content_type=content_type,
        )
        return RawResult(
            capability_id=ctx.capability_id,
            data=data,
            metadata={"status_code": status_code, "url": endpoint.url},
        )

    async def _read_error_snippet(self, response: httpx.Response, *, max_bytes: int = 512) -> str:
        """Read at most ``max_bytes`` of an error body for the failure message.

        Streams and stops early so an oversized error body cannot be buffered in
        full — the size guard must hold on the failure path too (#194). Only the
        first 200 characters are surfaced in the error message.

        Args:
            response: The open streaming response (already known to be an error).
            max_bytes: Hard cap on bytes read before giving up.

        Returns:
            A decoded, length-bounded snippet of the error body.
        """
        chunks = bytearray()
        async for chunk in response.aiter_bytes():
            chunks.extend(chunk)
            if len(chunks) >= max_bytes:
                break
        return bytes(chunks).decode("utf-8", "replace")[:200]

    async def _read_bounded(self, response: httpx.Response, *, url: str) -> bytes:
        """Read the response body, aborting if it exceeds ``max_response_bytes``.

        Streams chunks so an oversized upstream body is rejected before it is
        fully buffered — the firewall's budget only applies *after* a
        :class:`RawResult` exists, so the guard has to live here (#194).

        Args:
            response: The open streaming response.
            url: The request URL, used in the error message.

        Returns:
            The full response body as bytes.

        Raises:
            DriverError: If the accumulated body exceeds ``max_response_bytes``.
        """
        limit = self._max_response_bytes
        if limit is None:
            return await response.aread()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > limit:
                raise DriverError(
                    f"HTTPDriver '{self._driver_id}': response from {url} exceeded "
                    f"max_response_bytes ({limit})."
                )
        return bytes(body)

    def _decode_body(
        self,
        body: bytes,
        *,
        response_format: Literal["json", "text"],
        url: str,
        content_type: str,
    ) -> Any:
        """Decode a response body per the endpoint's ``response_format``.

        Args:
            body: The raw response bytes.
            response_format: ``"json"`` to parse, ``"text"`` to decode as a string.
            url: The request URL, used in the error message.
            content_type: The response ``Content-Type``, used in the error message.

        Returns:
            The parsed JSON value (``None`` for an empty body), or the decoded text.

        Raises:
            DriverError: If ``response_format`` is ``"json"`` and the body is not
                valid JSON (#197).
        """
        if response_format == "text":
            return body.decode("utf-8", "replace")
        try:
            return json.loads(body) if body else None
        except (json.JSONDecodeError, ValueError) as exc:
            snippet = body[:200].decode("utf-8", "replace")
            raise DriverError(
                f"HTTPDriver '{self._driver_id}': non-JSON response from {url} "
                f"(content-type: {content_type or 'unknown'}): {snippet}"
            ) from exc
