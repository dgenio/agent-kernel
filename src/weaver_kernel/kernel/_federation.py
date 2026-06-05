"""Federation method implementations for the :class:`Kernel`.

Split out of :mod:`kernel` to keep the public API module ≤ 300 lines
(AGENTS.md). Each function is the body of the corresponding ``Kernel``
method; the class method itself is a thin wrapper that adds logging
context.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Literal

import httpx

from ..drivers.base import Driver
from ..errors import FederationError
from ..federation import TrustPolicy, build_manifest, import_manifest
from ..federation_discovery import DiscoveryRateLimiter, discover_peers
from ..models import Capability, CapabilityManifest

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")


def perform_advertise(
    kernel: Kernel,
    *,
    endpoint: str,
    trust_level: Literal["verified", "unverified"],
) -> CapabilityManifest:
    """Build a public-facing :class:`CapabilityManifest` for *kernel*.

    Internal implementation details (driver IDs, operation names,
    ``parameters_model`` Python references) are stripped — only fields
    safe to share over the wire are emitted.
    """
    manifest = build_manifest(
        kernel_id=kernel.kernel_id,
        registry=kernel._registry,
        endpoint=endpoint,
        trust_level=trust_level,
    )
    logger.info(
        "advertise",
        extra={
            "kernel_id": kernel.kernel_id,
            "endpoint": endpoint,
            "capability_count": len(manifest.capabilities),
        },
    )
    return manifest


def perform_import_remote(
    kernel: Kernel,
    manifest: CapabilityManifest,
    *,
    driver: Driver,
    trust_policy: TrustPolicy,
) -> list[Capability]:
    """Register *manifest*'s capabilities into *kernel*'s registry."""
    # Imported capabilities must be routable. Require a mutable router up front
    # so we fail clean instead of registering capabilities that can never be
    # invoked.
    router_add = getattr(kernel._router, "add_route", None)
    if router_add is None:
        raise FederationError(
            "import_remote() requires a router that supports add_route(); "
            f"the configured {type(kernel._router).__name__} does not, so "
            "imported capabilities would be unroutable. Use a mutable router "
            "(e.g. StaticRouter) or pre-configure routes for the imported IDs."
        )
    kernel.register_driver(driver)
    imported = import_manifest(
        manifest=manifest,
        registry=kernel._registry,
        driver_id=driver.driver_id,
        trust_policy=trust_policy,
    )
    for cap in imported:
        router_add(cap.capability_id, [driver.driver_id])
    logger.info(
        "import_remote",
        extra={
            "kernel_id": kernel.kernel_id,
            "remote_kernel_id": manifest.kernel_id,
            "endpoint": manifest.endpoint,
            "capability_count": len(imported),
            "trust_policy": trust_policy,
            "driver_id": driver.driver_id,
        },
    )
    return imported


async def perform_discover_peers(
    kernel: Kernel,
    *,
    peer_urls: Iterable[str] | None,
    registry_url: str | None,
    secret: str | None,
    rate_limiter: DiscoveryRateLimiter | None,
    client: httpx.AsyncClient | None,
) -> list[CapabilityManifest]:
    """Fetch one or more :class:`CapabilityManifest` over HTTP."""
    manifests = await discover_peers(
        peer_urls=peer_urls,
        registry_url=registry_url,
        secret=secret,
        rate_limiter=rate_limiter,
        client=client,
    )
    logger.info(
        "discover_peers",
        extra={
            "kernel_id": kernel.kernel_id,
            "peer_count": len(manifests),
            "registry_url": registry_url,
        },
    )
    return manifests


__all__ = [
    "perform_advertise",
    "perform_discover_peers",
    "perform_import_remote",
]
