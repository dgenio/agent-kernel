"""Federated discovery + signed manifests (issue #51).

Builds on the local marketplace foundation in :mod:`federation` (issue
#52 — :class:`CapabilityManifest`, :func:`build_manifest`,
:func:`import_manifest`). This module adds the network-layer pieces:

* :func:`sign_manifest` / :func:`verify_manifest` — HMAC-signed payload
  envelopes so an importer can detect tampering.
* :func:`discover_peers` — async fetch of manifests from a registry URL
  or list of peer URLs, with per-discovery-call rate limiting.
* :func:`serve_manifest_payload` — a transport-agnostic helper that
  returns a signed-envelope JSON dict ready to be exposed by any ASGI
  framework (Starlette, FastAPI, Litestar, etc.).

Security boundary
-----------------

Discovery does not authorise capability execution by itself. Even after a
successful :func:`discover_peers` + :func:`Kernel.import_remote`, every
invocation still flows through the *local* policy → token → firewall
pipeline. Discovery only decides *what* capabilities a kernel might
import — not *how* it executes them. See :ref:`docs/federation.md`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import DiscoveryError, ManifestError, ManifestSignatureError
from .models import CapabilityManifest

SIGNATURE_ALGORITHM = "HMAC-SHA256"
"""Wire-level identifier embedded in every signed envelope."""

_DEFAULT_TIMEOUT_SECONDS = 5.0
"""Default per-request timeout used by :func:`discover_peers`."""


def sign_manifest(manifest: CapabilityManifest, *, secret: str) -> dict[str, Any]:
    """Wrap *manifest* in a signed envelope ready for transport.

    The envelope shape is::

        {
            "payload": "<json-encoded CapabilityManifest>",
            "algorithm": "HMAC-SHA256",
            "signature": "<hex HMAC over the payload>",
        }

    Splitting the JSON-encoded payload from the dict-level keys means
    the signature is over the *exact* bytes the importer will hash —
    canonicalisation differences (key ordering, whitespace) don't matter.

    Args:
        manifest: The manifest to sign.
        secret: Shared secret bound to the publishing kernel.

    Returns:
        A dict ready to be serialised as JSON.
    """
    payload = json.dumps(manifest.to_dict(), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "payload": payload.decode("utf-8"),
        "algorithm": SIGNATURE_ALGORITHM,
        "signature": signature,
    }


def verify_manifest(envelope: dict[str, Any], *, secret: str) -> CapabilityManifest:
    """Verify *envelope* and return the embedded :class:`CapabilityManifest`.

    Args:
        envelope: A signed envelope as produced by :func:`sign_manifest`.
        secret: Shared secret used to verify the signature.

    Raises:
        ManifestSignatureError: If the signature does not match.
        ManifestError: If the envelope is malformed.
    """
    if not isinstance(envelope, dict):
        raise ManifestError(f"Envelope must be a dict, got {type(envelope).__name__}.")
    for key in ("payload", "algorithm", "signature"):
        if key not in envelope:
            raise ManifestError(f"Envelope missing required key '{key}'.")
    if envelope["algorithm"] != SIGNATURE_ALGORITHM:
        raise ManifestSignatureError(
            f"Unsupported signature algorithm '{envelope['algorithm']}'; "
            f"expected '{SIGNATURE_ALGORITHM}'."
        )

    payload = envelope["payload"]
    if not isinstance(payload, str):
        raise ManifestError(f"Envelope 'payload' must be a string, got {type(payload).__name__}.")
    payload_bytes = payload.encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, envelope["signature"]):
        raise ManifestSignatureError(
            "Manifest signature mismatch — payload may be tampered, or the "
            "verification secret does not match the publisher's signing secret."
        )

    try:
        payload_data = json.loads(payload)
    except ValueError as exc:
        raise ManifestError(f"Envelope payload is not valid JSON: {exc}") from exc
    return CapabilityManifest.from_dict(payload_data)


def serve_manifest_payload(
    manifest: CapabilityManifest,
    *,
    secret: str | None = None,
) -> dict[str, Any]:
    """Return a JSON-serialisable payload for a manifest-serving HTTP route.

    If *secret* is provided the result is a signed envelope (per
    :func:`sign_manifest`); otherwise the bare manifest is returned. This
    helper is transport-agnostic — callers wire it into Starlette,
    FastAPI, Litestar, or any other ASGI framework.

    Args:
        manifest: The manifest to serve.
        secret: Optional HMAC secret for signing.
    """
    if secret is None:
        return manifest.to_dict()
    return sign_manifest(manifest, secret=secret)


@dataclass(slots=True)
class _RateLimitState:
    """Per-discovery-call rate-limit tracker."""

    timestamps: list[float]


class DiscoveryRateLimiter:
    """Sliding-window limiter scoped to discovery calls.

    Default budget: 10 calls per 60 seconds. Configurable per-instance.
    Backed by :func:`time.monotonic` so wall-clock changes don't affect
    behavior.
    """

    def __init__(self, *, limit: int = 10, window_seconds: float = 60.0) -> None:
        self._limit = limit
        self._window = window_seconds
        self._state = _RateLimitState(timestamps=[])

    def acquire(self) -> None:
        """Record a discovery call. Raises :class:`DiscoveryError` if over budget."""
        now = time.monotonic()
        cutoff = now - self._window
        self._state.timestamps = [t for t in self._state.timestamps if t > cutoff]
        if len(self._state.timestamps) >= self._limit:
            raise DiscoveryError(
                f"Discovery rate limit exceeded: {self._limit} calls per "
                f"{self._window}s. Wait and retry."
            )
        self._state.timestamps.append(now)


async def _fetch_manifest(
    client: httpx.AsyncClient,
    url: str,
    *,
    secret: str | None,
) -> CapabilityManifest:
    """Fetch one manifest from *url*. Used by :func:`discover_peers`."""
    try:
        response = await client.get(url, timeout=_DEFAULT_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"Network error fetching '{url}': {exc}") from exc

    if response.status_code != 200:
        raise DiscoveryError(f"Manifest endpoint '{url}' returned HTTP {response.status_code}.")

    try:
        body = response.json()
    except ValueError as exc:
        raise DiscoveryError(f"Manifest endpoint '{url}' returned non-JSON.") from exc

    # Auto-detect signed vs. bare manifest.
    if isinstance(body, dict) and "signature" in body and "payload" in body:
        if secret is None:
            raise ManifestSignatureError(
                f"Manifest at '{url}' is signed but no verification secret was "
                f"provided to discover_peers()."
            )
        return verify_manifest(body, secret=secret)
    if secret is not None:
        raise ManifestSignatureError(
            f"Manifest at '{url}' is unsigned but discover_peers() was called "
            f"with a verification secret — refusing to trust an unsigned "
            f"manifest when signing is expected."
        )
    if not isinstance(body, dict):
        raise DiscoveryError(
            f"Manifest at '{url}' must be a JSON object, got {type(body).__name__}."
        )
    try:
        return CapabilityManifest.from_dict(body)
    except ManifestError as exc:
        raise DiscoveryError(f"Malformed manifest at '{url}': {exc}") from exc


async def discover_peers(
    *,
    peer_urls: Iterable[str] | None = None,
    registry_url: str | None = None,
    secret: str | None = None,
    rate_limiter: DiscoveryRateLimiter | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[CapabilityManifest]:
    """Fetch one or more :class:`CapabilityManifest` from remote endpoints.

    Either *peer_urls* (direct manifest URLs) or *registry_url* (a URL
    returning a JSON list of peer URLs) must be provided.

    Args:
        peer_urls: Direct URLs that each return one manifest.
        registry_url: URL that returns a JSON list of peer manifest URLs.
        secret: HMAC secret for verifying signed manifests. Mandatory if
            the manifest endpoint produces signed envelopes; refusing
            unsigned manifests in that case is an explicit security
            choice (see :func:`_fetch_manifest`).
        rate_limiter: Optional :class:`DiscoveryRateLimiter`. Defaults to
            a fresh limiter (10 calls / 60s).
        client: Optional pre-configured :class:`httpx.AsyncClient` for
            test injection. A new ephemeral client is created if omitted.

    Returns:
        A list of :class:`CapabilityManifest` objects in the order they
        were resolved.

    Raises:
        DiscoveryError: If the network call fails, the response is
            malformed, or the rate limit is exhausted.
        ManifestSignatureError: If a signed manifest fails verification.
    """
    if not peer_urls and not registry_url:
        raise DiscoveryError("discover_peers() requires peer_urls or registry_url.")

    limiter = rate_limiter or DiscoveryRateLimiter()
    owns_client = client is None
    transport_client = client or httpx.AsyncClient()

    try:
        urls: list[str] = list(peer_urls or [])
        if registry_url is not None:
            limiter.acquire()
            try:
                response = await transport_client.get(
                    registry_url, timeout=_DEFAULT_TIMEOUT_SECONDS
                )
            except httpx.HTTPError as exc:
                raise DiscoveryError(
                    f"Network error fetching registry '{registry_url}': {exc}"
                ) from exc
            if response.status_code != 200:
                raise DiscoveryError(
                    f"Registry '{registry_url}' returned HTTP {response.status_code}."
                )
            try:
                registry_body = response.json()
            except ValueError as exc:
                raise DiscoveryError(f"Registry '{registry_url}' returned non-JSON.") from exc
            if not isinstance(registry_body, list) or not all(
                isinstance(u, str) for u in registry_body
            ):
                raise DiscoveryError(
                    f"Registry '{registry_url}' must return a JSON list of URL strings."
                )
            urls.extend(registry_body)

        manifests: list[CapabilityManifest] = []
        for url in urls:
            limiter.acquire()
            manifests.append(await _fetch_manifest(transport_client, url, secret=secret))
            # Yield to the event loop between fetches so the limiter's
            # monotonic clock advances measurably even on a fast network.
            await asyncio.sleep(0)
        return manifests
    finally:
        if owns_client:
            await transport_client.aclose()


__all__ = [
    "SIGNATURE_ALGORITHM",
    "DiscoveryRateLimiter",
    "discover_peers",
    "serve_manifest_payload",
    "sign_manifest",
    "verify_manifest",
]
