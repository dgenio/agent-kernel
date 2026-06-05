"""Tests for federated discovery + signed manifests (issue #51).

Uses `httpx.MockTransport` so tests are fully offline. Each scenario
pins one contract from the issue's acceptance criteria:

* Signed manifest round-trip + tamper detection.
* `discover_peers` via direct peer URLs.
* `discover_peers` via a registry URL.
* Rate limiting on discovery.
* Kernel-scoped HMAC isolation when an imported capability is invoked.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

import httpx
import pytest

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    DiscoveryError,
    DiscoveryRateLimiter,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    ManifestSignatureError,
    SafetyClass,
    discover_peers,
    serve_manifest_payload,
    sign_manifest,
    verify_manifest,
)
from weaver_kernel.federation import build_manifest
from weaver_kernel.models import CapabilityManifest


def _build_test_manifest() -> CapabilityManifest:
    cap = Capability(
        capability_id="metrics.read",
        name="read",
        description="Read a metric.",
        safety_class=SafetyClass.READ,
    )
    registry = CapabilityRegistry()
    registry.register(cap)
    return build_manifest(
        kernel_id="peer-a",
        registry=registry,
        endpoint="https://peer-a.invalid/kernel",
        trust_level="unverified",
    )


def test_sign_and_verify_round_trip() -> None:
    """`sign_manifest` then `verify_manifest` returns the original manifest."""
    manifest = _build_test_manifest()
    envelope = sign_manifest(manifest, secret="shared-secret")
    assert envelope["algorithm"] == "HMAC-SHA256"
    assert envelope["signature"]
    assert envelope["payload"]

    decoded = verify_manifest(envelope, secret="shared-secret")
    assert decoded.kernel_id == manifest.kernel_id
    assert decoded.endpoint == manifest.endpoint
    assert [c.capability_id for c in decoded.capabilities] == [
        c.capability_id for c in manifest.capabilities
    ]


def test_verify_manifest_rejects_tampered_payload() -> None:
    """Modifying the payload after signing must fail verification."""
    manifest = _build_test_manifest()
    envelope = sign_manifest(manifest, secret="shared-secret")
    tampered_payload = json.loads(envelope["payload"])
    tampered_payload["kernel_id"] = "attacker"
    envelope["payload"] = json.dumps(tampered_payload, sort_keys=True)

    with pytest.raises(ManifestSignatureError, match="signature mismatch"):
        verify_manifest(envelope, secret="shared-secret")


def test_verify_manifest_rejects_wrong_secret() -> None:
    """Wrong verification secret must fail signature check."""
    manifest = _build_test_manifest()
    envelope = sign_manifest(manifest, secret="publisher-secret")
    with pytest.raises(ManifestSignatureError, match="signature mismatch"):
        verify_manifest(envelope, secret="other-secret")


def test_serve_manifest_payload_signed_and_unsigned() -> None:
    """`serve_manifest_payload` produces a bare dict or signed envelope."""
    manifest = _build_test_manifest()
    bare = serve_manifest_payload(manifest)
    assert "signature" not in bare
    assert bare["kernel_id"] == "peer-a"

    signed = serve_manifest_payload(manifest, secret="s")
    assert signed["algorithm"] == "HMAC-SHA256"
    assert signed["signature"]


@pytest.mark.asyncio
async def test_discover_peers_via_direct_peer_urls() -> None:
    """`discover_peers(peer_urls=...)` returns one manifest per URL."""
    manifest = _build_test_manifest()
    payload = json.dumps(manifest.to_dict())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=payload, headers={"content-type": "application/json"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await discover_peers(
            peer_urls=["http://peer-a.example/manifest", "http://peer-b.example/manifest"],
            client=client,
        )

    assert len(result) == 2
    assert all(m.kernel_id == "peer-a" for m in result)


@pytest.mark.asyncio
async def test_discover_peers_via_registry_url() -> None:
    """`discover_peers(registry_url=...)` first fetches the registry list."""
    manifest = _build_test_manifest()
    manifest_payload = json.dumps(manifest.to_dict())

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/registry"):
            return httpx.Response(
                200,
                text=json.dumps(["http://peer-a.example/manifest"]),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            200, text=manifest_payload, headers={"content-type": "application/json"}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await discover_peers(
            registry_url="http://central.example/registry",
            client=client,
        )

    assert len(result) == 1
    assert result[0].kernel_id == "peer-a"


@pytest.mark.asyncio
async def test_discover_peers_rejects_unsigned_when_secret_provided() -> None:
    """Calling with a secret but receiving an unsigned manifest is an error."""
    manifest = _build_test_manifest()
    payload = json.dumps(manifest.to_dict())  # Unsigned.

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=payload, headers={"content-type": "application/json"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ManifestSignatureError, match="unsigned"):
            await discover_peers(
                peer_urls=["http://peer-a.example/manifest"],
                secret="expected-secret",
                client=client,
            )


@pytest.mark.asyncio
async def test_discover_peers_rejects_signed_when_no_secret_provided() -> None:
    """Calling without a secret but receiving a signed envelope is an error."""
    manifest = _build_test_manifest()
    signed_payload = json.dumps(sign_manifest(manifest, secret="s"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text=signed_payload, headers={"content-type": "application/json"}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ManifestSignatureError, match="signed but no verification"):
            await discover_peers(
                peer_urls=["http://peer-a.example/manifest"],
                client=client,
            )


@pytest.mark.asyncio
async def test_discover_peers_handles_signed_manifest_end_to_end() -> None:
    """Signed envelopes are verified and the embedded manifest is returned."""
    manifest = _build_test_manifest()
    signed_payload = json.dumps(sign_manifest(manifest, secret="shared"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text=signed_payload, headers={"content-type": "application/json"}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await discover_peers(
            peer_urls=["http://peer-a.example/manifest"],
            secret="shared",
            client=client,
        )
    assert len(result) == 1
    assert result[0].kernel_id == "peer-a"


@pytest.mark.asyncio
async def test_discover_peers_network_error_raises_discovery_error() -> None:
    """HTTP errors are wrapped in :class:`DiscoveryError`."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="service unavailable")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(DiscoveryError, match="HTTP 503"):
            await discover_peers(
                peer_urls=["http://peer-a.example/manifest"],
                client=client,
            )


@pytest.mark.asyncio
async def test_discover_peers_rate_limit() -> None:
    """`DiscoveryRateLimiter` rejects calls beyond the configured limit."""
    manifest = _build_test_manifest()
    payload = json.dumps(manifest.to_dict())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=payload, headers={"content-type": "application/json"})

    transport = httpx.MockTransport(handler)
    limiter = DiscoveryRateLimiter(limit=2, window_seconds=60.0)
    async with httpx.AsyncClient(transport=transport) as client:
        await discover_peers(
            peer_urls=["http://peer-a.example/manifest"],
            rate_limiter=limiter,
            client=client,
        )
        await discover_peers(
            peer_urls=["http://peer-b.example/manifest"],
            rate_limiter=limiter,
            client=client,
        )
        with pytest.raises(DiscoveryError, match="rate limit exceeded"):
            await discover_peers(
                peer_urls=["http://peer-c.example/manifest"],
                rate_limiter=limiter,
                client=client,
            )


@pytest.mark.asyncio
async def test_discover_peers_requires_some_input() -> None:
    """Calling with neither peer_urls nor registry_url is an error."""
    with pytest.raises(DiscoveryError, match="requires peer_urls or registry_url"):
        await discover_peers()


@pytest.mark.asyncio
async def test_kernel_discover_peers_integration() -> None:
    """`Kernel.discover_peers` is wired to fetch manifests over HTTP."""
    manifest = _build_test_manifest()
    payload = json.dumps(manifest.to_dict())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=payload, headers={"content-type": "application/json"})

    # Build a kernel without registering the peer-a capability locally.
    registry = CapabilityRegistry()
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="local-test-secret"),
    )

    # Monkey-patch where the kernel sub-module imported `discover_peers`,
    # not the source module — `_federation.py` already bound a local name.
    import weaver_kernel.kernel._federation as kf

    original = kf.discover_peers

    async def patched_discover(**kwargs: Any) -> list[CapabilityManifest]:
        # `perform_discover_peers` passes ``client=None`` explicitly, so
        # ``setdefault`` won't override — replace the key unconditionally.
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            kwargs["client"] = client
            return await original(**kwargs)

    kf.discover_peers = patched_discover  # type: ignore[assignment]
    try:
        result = await kernel.discover_peers(peer_urls=["http://peer-a.example/manifest"])
    finally:
        kf.discover_peers = original  # type: ignore[assignment]

    assert len(result) == 1
    assert result[0].kernel_id == "peer-a"


def test_kernel_scoped_hmac_isolation_for_imported_capability() -> None:
    """A token issued by kernel A must not validate against kernel B.

    Confused-deputy regression test that pins issue #51's acceptance
    criterion: HMAC tokens are kernel-scoped.
    """
    # Kernel A — publishes a capability.
    cap = Capability(
        capability_id="metrics.read",
        name="read",
        description="Read.",
        safety_class=SafetyClass.READ,
    )
    registry_a = CapabilityRegistry()
    registry_a.register(cap)
    kernel_a = Kernel(
        registry=registry_a,
        token_provider=HMACTokenProvider(secret="kernel-a-secret"),
        kernel_id="kernel-a",
    )
    kernel_a.register_driver(InMemoryDriver(driver_id="dummy-a"))

    # Kernel B — imports the manifest, different secret.
    manifest = kernel_a.advertise(endpoint="https://kernel-a.invalid/")
    registry_b = CapabilityRegistry()
    kernel_b = Kernel(
        registry=registry_b,
        token_provider=HMACTokenProvider(secret="kernel-b-secret"),
        kernel_id="kernel-b",
    )
    kernel_b.import_remote(manifest, driver=InMemoryDriver(driver_id="dummy-b"))

    # Mint a token on kernel A.
    from weaver_kernel import Principal
    from weaver_kernel.errors import TokenInvalid
    from weaver_kernel.models import CapabilityRequest

    principal = Principal(principal_id="alice", roles=["reader"])
    req = CapabilityRequest(capability_id="metrics.read", goal="t")
    token_from_a = kernel_a.get_token(req, principal, justification="")

    # Kernel B refuses tokens signed by kernel A's secret.
    with pytest.raises(TokenInvalid):
        kernel_b._token_provider.verify(  # type: ignore[attr-defined]
            token_from_a,
            expected_principal_id="alice",
            expected_capability_id="metrics.read",
        )


@pytest.mark.asyncio
async def test_signed_envelope_payload_is_canonical_json() -> None:
    """The signed envelope's payload is sorted-key JSON for determinism."""
    manifest = _build_test_manifest()
    envelope1 = sign_manifest(manifest, secret="s")
    envelope2 = sign_manifest(manifest, secret="s")
    # Same manifest, same secret → byte-identical envelope.
    assert envelope1 == envelope2


@pytest.mark.asyncio
async def test_verify_manifest_rejects_malformed_envelope() -> None:
    """Missing keys produce a clear error."""
    from weaver_kernel.errors import ManifestError

    with pytest.raises(ManifestError, match="missing required key"):
        verify_manifest({"signature": "x"}, secret="s")

    with pytest.raises(ManifestError, match="must be a dict"):
        verify_manifest([], secret="s")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_verify_manifest_rejects_unknown_algorithm() -> None:
    """Unknown algorithm is rejected before signature check."""
    with pytest.raises(ManifestSignatureError, match="Unsupported"):
        verify_manifest(
            {"payload": "{}", "algorithm": "NOT-A-REAL-ALG", "signature": "x"},
            secret="s",
        )


# silence flake about unused datetime import — kept for parity with peer modules.
_ = datetime
