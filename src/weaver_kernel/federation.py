"""Capability marketplace — manifest format and local-registry federation.

This module implements *part 1* of the capability marketplace protocol
(issue #52): one kernel can advertise its capabilities as a
:class:`~weaver_kernel.models.CapabilityManifest`, and a second kernel can
import that manifest to extend its own registry. Remote invocation is then
performed by routing imported capabilities to a caller-supplied
:class:`~weaver_kernel.drivers.base.Driver` (typically an
:class:`~weaver_kernel.drivers.http.HTTPDriver` or
:class:`~weaver_kernel.drivers.mcp.MCPDriver`) — every imported call still
flows through the *local* policy → token → firewall pipeline, satisfying
weaver-spec I-01 / I-02 / I-06.

Discovery (part 2 of the marketplace, issue #51) is out of scope here — this
module is purely local. Manifests are constructed by ``Kernel.advertise()``
and consumed by ``Kernel.import_remote()``; the importing side is free to
fetch them by any transport.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from .enums import SensitivityTag
from .errors import ManifestError, TrustPolicyError
from .models import (
    Capability,
    CapabilityDescriptor,
    CapabilityManifest,
    ImplementationRef,
)

if TYPE_CHECKING:
    from .registry import CapabilityRegistry

MANIFEST_VERSION = "1"
"""Schema version published by :func:`build_manifest`."""

TrustPolicy = Literal["most_restrictive", "local_only", "remote_deferred"]
"""How an importing kernel weighs descriptor metadata against its own policy.

- ``"most_restrictive"`` (default): the descriptor's sensitivity tag is
  honoured as a floor — even if the importing kernel's policy would treat
  the capability as ``NONE``, the imported capability keeps the remote tag.
  Required by use cases that span trust boundaries.
- ``"local_only"``: the importing kernel ignores the descriptor's
  sensitivity tag and registers the imported capability with
  :attr:`~weaver_kernel.enums.SensitivityTag.NONE`. Use when the importer
  owns both kernels and has a single canonical policy.
- ``"remote_deferred"``: the descriptor's sensitivity tag is preserved
  verbatim and treated as the remote policy's input; the importing kernel
  layers its own policy on top.
"""

_VALID_TRUST_POLICIES: frozenset[str] = frozenset(
    {"most_restrictive", "local_only", "remote_deferred"}
)

# Ordering used by ``most_restrictive`` when picking between two sensitivity
# tags. The strictest tag wins. Every SensitivityTag member must appear here —
# a missing tag would default to rank 0 in ``_stricter`` and be silently
# downgraded to NONE. ``test_every_sensitivity_tag_outranks_none`` guards this.
_SENSITIVITY_RANK: dict[SensitivityTag, int] = {
    SensitivityTag.NONE: 0,
    SensitivityTag.MEMORY: 1,
    SensitivityTag.PII: 2,
    SensitivityTag.PCI: 3,
    SensitivityTag.SECRETS: 4,
}


def _stricter(a: SensitivityTag, b: SensitivityTag) -> SensitivityTag:
    """Return the stricter of two sensitivity tags (higher rank wins)."""
    if _SENSITIVITY_RANK.get(b, 0) > _SENSITIVITY_RANK.get(a, 0):
        return b
    return a


def build_manifest(
    *,
    kernel_id: str,
    registry: CapabilityRegistry,
    endpoint: str,
    trust_level: Literal["verified", "unverified"] = "unverified",
) -> CapabilityManifest:
    """Build a public-facing :class:`CapabilityManifest` for *registry*.

    Internal implementation details (``ImplementationRef``, ``parameters_model``
    Python references, ``tool_hints``) are stripped — only fields safe to share
    over the wire are emitted.

    Args:
        kernel_id: Stable identifier of the advertising kernel.
        registry: The :class:`CapabilityRegistry` whose contents to publish.
        endpoint: Transport endpoint at which the advertising kernel can be
            reached. Format is transport-specific (e.g.
            ``"https://agent-a.example/kernel"``).
        trust_level: Publisher-declared trust hint. The importing kernel still
            applies its configured trust policy regardless.

    Returns:
        A :class:`CapabilityManifest` ready to be serialised with
        :meth:`CapabilityManifest.to_dict`.
    """
    descriptors = [_descriptor_for(cap) for cap in registry.list_all()]
    return CapabilityManifest(
        kernel_id=kernel_id,
        version=MANIFEST_VERSION,
        capabilities=descriptors,
        endpoint=endpoint,
        trust_level=trust_level,
    )


def _descriptor_for(cap: Capability) -> CapabilityDescriptor:
    """Project a :class:`Capability` onto its safe-to-share descriptor view."""
    return CapabilityDescriptor(
        capability_id=cap.capability_id,
        name=cap.name,
        description=cap.description,
        safety_class=cap.safety_class,
        sensitivity=cap.sensitivity,
        tags=list(cap.tags),
        parameters_schema=cap.parameters_schema,
    )


def import_manifest(
    *,
    manifest: CapabilityManifest,
    registry: CapabilityRegistry,
    driver_id: str,
    trust_policy: TrustPolicy = "most_restrictive",
) -> list[Capability]:
    """Register a remote manifest's capabilities into *registry*.

    Each descriptor becomes a regular :class:`Capability` whose
    :class:`ImplementationRef` points at the caller-supplied *driver_id*.
    The importing kernel must register a matching driver with
    :meth:`~weaver_kernel.Kernel.register_driver`. Invocations on the
    resulting capability flow through the full local pipeline — the remote
    endpoint is never trusted to perform policy, token verification, or
    firewall transformation on behalf of the importer.

    Args:
        manifest: The remote :class:`CapabilityManifest` to import.
        registry: The local :class:`CapabilityRegistry` to extend.
        driver_id: The local driver ID that will execute imported capabilities.
            The caller is responsible for registering a driver with that ID
            (typically an :class:`~weaver_kernel.drivers.http.HTTPDriver` or
            :class:`~weaver_kernel.drivers.mcp.MCPDriver` configured for
            ``manifest.endpoint``).
        trust_policy: How the importer weighs the manifest's sensitivity
            metadata. See :data:`TrustPolicy`.

    Returns:
        The list of imported :class:`Capability` objects, in manifest order.

    Raises:
        TrustPolicyError: If *trust_policy* is not one of the documented values.
        ManifestError: If the manifest is malformed (missing fields, wrong
            version), contains a capability ID already registered locally, or
            lists the same capability ID more than once. The registry is left
            untouched when this is raised.
    """
    if trust_policy not in _VALID_TRUST_POLICIES:
        raise TrustPolicyError(
            f"Unknown trust_policy '{trust_policy}'. "
            f"Expected one of: {sorted(_VALID_TRUST_POLICIES)}."
        )
    if manifest.version != MANIFEST_VERSION:
        raise ManifestError(
            f"Manifest version '{manifest.version}' is not supported by this "
            f"kernel (expected '{MANIFEST_VERSION}'). Upgrade agent-kernel or "
            "re-publish the manifest with the supported version."
        )
    if not manifest.endpoint:
        raise ManifestError(
            f"Manifest from kernel '{manifest.kernel_id}' has no endpoint. "
            "Endpoints are required so the local kernel can route imported "
            "capabilities to a driver."
        )

    # Validate the whole batch before registering anything so a malformed
    # manifest leaves the registry untouched (all-or-nothing import). A
    # mid-loop failure would otherwise leave capabilities registered but
    # unrouted, since the caller adds routes only after this returns.
    existing = {cap.capability_id for cap in registry.list_all()}
    seen: set[str] = set()
    for descriptor in manifest.capabilities:
        cap_id = descriptor.capability_id
        if cap_id in existing:
            raise ManifestError(
                f"Manifest from kernel '{manifest.kernel_id}' contains capability "
                f"'{cap_id}', which is already registered locally. Imported "
                "capability IDs must be unique; unregister or rename the existing "
                "capability before importing."
            )
        if cap_id in seen:
            raise ManifestError(
                f"Manifest from kernel '{manifest.kernel_id}' lists capability "
                f"'{cap_id}' more than once. Capability IDs within a manifest "
                "must be unique."
            )
        seen.add(cap_id)

    imported: list[Capability] = []
    for descriptor in manifest.capabilities:
        cap = _capability_for_import(
            descriptor=descriptor,
            driver_id=driver_id,
            trust_policy=trust_policy,
        )
        registry.register(cap)
        imported.append(cap)
    return imported


def _capability_for_import(
    *,
    descriptor: CapabilityDescriptor,
    driver_id: str,
    trust_policy: TrustPolicy,
) -> Capability:
    """Materialise a local :class:`Capability` from a remote descriptor."""
    sensitivity = _resolve_sensitivity(descriptor.sensitivity, trust_policy)
    # The descriptor never exposes a driver-side operation name; we mirror
    # the convention used everywhere else in the kernel: drivers resolve
    # ``args.get("operation", capability_id)``. Imported capabilities therefore
    # default operation to the capability_id.
    impl = ImplementationRef(driver_id=driver_id, operation=descriptor.capability_id)
    return Capability(
        capability_id=descriptor.capability_id,
        name=descriptor.name,
        description=descriptor.description,
        safety_class=descriptor.safety_class,
        sensitivity=sensitivity,
        tags=list(descriptor.tags),
        impl=impl,
        parameters_schema=descriptor.parameters_schema,
    )


def _resolve_sensitivity(remote: SensitivityTag, trust_policy: TrustPolicy) -> SensitivityTag:
    """Apply *trust_policy* to a remote sensitivity tag.

    ``most_restrictive`` and ``remote_deferred`` both keep the remote tag —
    they differ only in which side's *policy engine* is consulted at
    invocation time, which is part 2 of the marketplace work. ``local_only``
    strips the remote sensitivity entirely.
    """
    if trust_policy == "local_only":
        return SensitivityTag.NONE
    return remote


def merge_sensitivity(local: SensitivityTag, remote: SensitivityTag) -> SensitivityTag:
    """Return the stricter of *local* and *remote* sensitivity tags.

    Exposed for callers that maintain their own capability records outside
    the registry and want the canonical ``most_restrictive`` union rule.

    Args:
        local: The locally-known sensitivity tag.
        remote: The sensitivity tag advertised by a remote/federated source.

    Returns:
        The stricter (more restrictive) of the two tags.
    """
    return _stricter(local, remote)


__all__ = [
    "MANIFEST_VERSION",
    "TrustPolicy",
    "build_manifest",
    "import_manifest",
    "merge_sensitivity",
]
