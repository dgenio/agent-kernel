"""Tests for the capability marketplace — manifest format & local registry (#52)."""

from __future__ import annotations

import asyncio

import pytest

from agent_kernel import (
    Capability,
    CapabilityDescriptor,
    CapabilityManifest,
    CapabilityRegistry,
    HMACTokenProvider,
    ImplementationRef,
    InMemoryDriver,
    Kernel,
    ManifestError,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    TokenInvalid,
    TrustPolicyError,
    build_manifest,
    import_manifest,
    merge_sensitivity,
)
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.federation import MANIFEST_VERSION
from agent_kernel.models import CapabilityRequest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_cap(cap_id: str, **kwargs: object) -> Capability:
    defaults: dict[str, object] = {
        "name": cap_id.replace(".", " ").title(),
        "description": f"Description for {cap_id}",
        "safety_class": SafetyClass.READ,
    }
    defaults.update(kwargs)
    return Capability(capability_id=cap_id, **defaults)  # type: ignore[arg-type]


def _remote_kernel_with(*caps: Capability) -> Kernel:
    reg = CapabilityRegistry()
    for cap in caps:
        reg.register(cap)
    return Kernel(
        registry=reg,
        token_provider=HMACTokenProvider(secret="remote-kernel-secret"),
        router=StaticRouter(),
        kernel_id="agent-b",
    )


# ── Manifest serialisation ────────────────────────────────────────────────────


def test_capability_descriptor_roundtrip() -> None:
    descriptor = CapabilityDescriptor(
        capability_id="billing.invoices.list",
        name="List Invoices",
        description="List recent invoices",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.PII,
        tags=["billing", "invoices"],
        parameters_schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
    )
    restored = CapabilityDescriptor.from_dict(descriptor.to_dict())
    assert restored == descriptor


def test_capability_manifest_to_dict_is_json_compatible() -> None:
    import json

    manifest = CapabilityManifest(
        kernel_id="agent-a",
        version=MANIFEST_VERSION,
        endpoint="https://agent-a.example/kernel",
        trust_level="verified",
        capabilities=[
            CapabilityDescriptor(
                capability_id="billing.list_invoices",
                name="List Invoices",
                description="List recent invoices",
                safety_class=SafetyClass.READ,
                sensitivity=SensitivityTag.PII,
                tags=["billing"],
            ),
        ],
    )
    payload = json.dumps(manifest.to_dict())
    restored = CapabilityManifest.from_dict(json.loads(payload))
    assert restored == manifest


def test_build_manifest_strips_internal_implementation_details() -> None:
    reg = CapabilityRegistry()
    reg.register(
        Capability(
            capability_id="billing.list_invoices",
            name="List Invoices",
            description="List recent invoices",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            tags=["billing"],
            impl=ImplementationRef(driver_id="secret_internal_driver", operation="op_x"),
        )
    )
    manifest = build_manifest(
        kernel_id="agent-a",
        registry=reg,
        endpoint="https://agent-a.example/kernel",
    )
    payload = manifest.to_dict()
    serialised = repr(payload)
    assert "secret_internal_driver" not in serialised
    assert "op_x" not in serialised
    # Public-facing fields are present.
    cap_dict = payload["capabilities"][0]
    assert cap_dict["capability_id"] == "billing.list_invoices"
    assert cap_dict["sensitivity"] == SensitivityTag.PII.value


def test_build_manifest_preserves_registration_order() -> None:
    reg = CapabilityRegistry()
    for cid in ["c.three", "a.one", "b.two"]:
        reg.register(_make_cap(cid))
    manifest = build_manifest(kernel_id="agent-a", registry=reg, endpoint="https://agent-a/k")
    assert [c.capability_id for c in manifest.capabilities] == ["c.three", "a.one", "b.two"]


def test_descriptor_from_dict_missing_field_raises_manifest_error() -> None:
    with pytest.raises(ManifestError, match="missing required field 'name'"):
        CapabilityDescriptor.from_dict({"capability_id": "billing.list", "safety_class": "read"})


def test_descriptor_from_dict_invalid_safety_class_raises_manifest_error() -> None:
    with pytest.raises(ManifestError, match="'safety_class' has invalid value"):
        CapabilityDescriptor.from_dict(
            {
                "capability_id": "billing.list",
                "name": "List",
                "description": "d",
                "safety_class": "not-a-class",
            }
        )


def test_manifest_from_dict_missing_field_raises_manifest_error() -> None:
    with pytest.raises(ManifestError, match="missing required field 'capabilities'"):
        CapabilityManifest.from_dict(
            {"kernel_id": "agent-b", "version": "1", "endpoint": "https://b/k"}
        )


def test_manifest_from_dict_capabilities_not_a_list_raises_manifest_error() -> None:
    with pytest.raises(ManifestError, match="'capabilities' must be a list"):
        CapabilityManifest.from_dict(
            {
                "kernel_id": "agent-b",
                "version": "1",
                "endpoint": "https://b/k",
                "capabilities": {"not": "a list"},
            }
        )


def test_manifest_from_dict_invalid_trust_level_raises_manifest_error() -> None:
    with pytest.raises(ManifestError, match="'trust_level' has invalid value"):
        CapabilityManifest.from_dict(
            {
                "kernel_id": "agent-b",
                "version": "1",
                "endpoint": "https://b/k",
                "trust_level": "super-trusted",
                "capabilities": [],
            }
        )


# ── Importing manifests ───────────────────────────────────────────────────────


def test_import_manifest_registers_capabilities_with_driver_routing() -> None:
    remote_kernel = _remote_kernel_with(_make_cap("billing.list_invoices"))
    manifest = remote_kernel.advertise(endpoint="https://agent-b.example/kernel")

    local_reg = CapabilityRegistry()
    imported = import_manifest(
        manifest=manifest,
        registry=local_reg,
        driver_id="remote_b",
        trust_policy="most_restrictive",
    )
    assert len(imported) == 1
    cap = local_reg.get("billing.list_invoices")
    assert cap.impl is not None
    assert cap.impl.driver_id == "remote_b"
    assert cap.impl.operation == "billing.list_invoices"


def test_import_manifest_rejects_unknown_trust_policy() -> None:
    manifest = CapabilityManifest(
        kernel_id="agent-b",
        version=MANIFEST_VERSION,
        endpoint="https://agent-b/k",
        capabilities=[],
    )
    with pytest.raises(TrustPolicyError, match="Unknown trust_policy"):
        import_manifest(
            manifest=manifest,
            registry=CapabilityRegistry(),
            driver_id="x",
            trust_policy="totally_made_up",  # type: ignore[arg-type]
        )


def test_import_manifest_rejects_unsupported_version() -> None:
    manifest = CapabilityManifest(
        kernel_id="agent-b",
        version="999",
        endpoint="https://agent-b/k",
        capabilities=[],
    )
    with pytest.raises(ManifestError, match="version '999' is not supported"):
        import_manifest(manifest=manifest, registry=CapabilityRegistry(), driver_id="x")


def test_import_manifest_rejects_empty_endpoint() -> None:
    manifest = CapabilityManifest(
        kernel_id="agent-b",
        version=MANIFEST_VERSION,
        endpoint="",
        capabilities=[],
    )
    with pytest.raises(ManifestError, match="has no endpoint"):
        import_manifest(manifest=manifest, registry=CapabilityRegistry(), driver_id="x")


def test_import_manifest_local_duplicate_raises_and_is_atomic() -> None:
    local = CapabilityRegistry()
    local.register(_make_cap("billing.list_invoices"))
    remote = _remote_kernel_with(
        _make_cap("crm.new_contact"),
        _make_cap("billing.list_invoices"),  # collides with the local capability
    )
    manifest = remote.advertise(endpoint="https://agent-b/k")
    with pytest.raises(ManifestError, match="already registered locally"):
        import_manifest(manifest=manifest, registry=local, driver_id="remote_b")
    # All-or-nothing: the non-colliding capability must not have been registered.
    assert "crm.new_contact" not in {c.capability_id for c in local.list_all()}


def test_import_manifest_in_manifest_duplicate_raises() -> None:
    dup = CapabilityDescriptor(
        capability_id="billing.list_invoices",
        name="List Invoices",
        description="List recent invoices",
        safety_class=SafetyClass.READ,
    )
    manifest = CapabilityManifest(
        kernel_id="agent-b",
        version=MANIFEST_VERSION,
        endpoint="https://agent-b/k",
        capabilities=[dup, dup],
    )
    local = CapabilityRegistry()
    with pytest.raises(ManifestError, match="more than once"):
        import_manifest(manifest=manifest, registry=local, driver_id="remote_b")
    assert local.list_all() == []


# ── Trust policies ────────────────────────────────────────────────────────────


def test_trust_policy_most_restrictive_preserves_sensitivity() -> None:
    remote = _remote_kernel_with(_make_cap("crm.contacts.list", sensitivity=SensitivityTag.PII))
    manifest = remote.advertise(endpoint="https://agent-b/k")
    local_reg = CapabilityRegistry()
    import_manifest(
        manifest=manifest,
        registry=local_reg,
        driver_id="remote_b",
        trust_policy="most_restrictive",
    )
    assert local_reg.get("crm.contacts.list").sensitivity == SensitivityTag.PII


def test_trust_policy_local_only_strips_sensitivity() -> None:
    remote = _remote_kernel_with(_make_cap("crm.contacts.list", sensitivity=SensitivityTag.PII))
    manifest = remote.advertise(endpoint="https://agent-b/k")
    local_reg = CapabilityRegistry()
    import_manifest(
        manifest=manifest,
        registry=local_reg,
        driver_id="remote_b",
        trust_policy="local_only",
    )
    assert local_reg.get("crm.contacts.list").sensitivity == SensitivityTag.NONE


def test_trust_policy_remote_deferred_preserves_sensitivity() -> None:
    remote = _remote_kernel_with(_make_cap("crm.contacts.list", sensitivity=SensitivityTag.PII))
    manifest = remote.advertise(endpoint="https://agent-b/k")
    local_reg = CapabilityRegistry()
    import_manifest(
        manifest=manifest,
        registry=local_reg,
        driver_id="remote_b",
        trust_policy="remote_deferred",
    )
    assert local_reg.get("crm.contacts.list").sensitivity == SensitivityTag.PII


def test_merge_sensitivity_picks_strictest() -> None:
    assert merge_sensitivity(SensitivityTag.NONE, SensitivityTag.PII) == SensitivityTag.PII
    assert merge_sensitivity(SensitivityTag.PII, SensitivityTag.NONE) == SensitivityTag.PII
    assert merge_sensitivity(SensitivityTag.PII, SensitivityTag.PCI) == SensitivityTag.PCI
    assert merge_sensitivity(SensitivityTag.PCI, SensitivityTag.SECRETS) == SensitivityTag.SECRETS
    assert merge_sensitivity(SensitivityTag.NONE, SensitivityTag.NONE) == SensitivityTag.NONE
    assert merge_sensitivity(SensitivityTag.NONE, SensitivityTag.MEMORY) == SensitivityTag.MEMORY


@pytest.mark.parametrize("tag", [t for t in SensitivityTag if t is not SensitivityTag.NONE])
def test_every_sensitivity_tag_outranks_none(tag: SensitivityTag) -> None:
    # Guards against a SensitivityTag being added without a rank: an unranked
    # tag would default to NONE's rank and be silently downgraded on merge.
    assert merge_sensitivity(SensitivityTag.NONE, tag) == tag
    assert merge_sensitivity(tag, SensitivityTag.NONE) == tag


# ── Kernel.advertise() / Kernel.import_remote() ───────────────────────────────


def test_kernel_advertise_uses_kernel_id() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.list_invoices"))
    kernel = Kernel(
        registry=reg,
        token_provider=HMACTokenProvider(secret="k1"),
        kernel_id="my-fancy-kernel",
    )
    manifest = kernel.advertise(endpoint="https://my-kernel/k")
    assert manifest.kernel_id == "my-fancy-kernel"
    assert manifest.endpoint == "https://my-kernel/k"
    assert manifest.version == MANIFEST_VERSION


def test_kernel_import_remote_registers_driver_and_route() -> None:
    remote = _remote_kernel_with(_make_cap("billing.list_invoices"))
    manifest = remote.advertise(endpoint="https://agent-b/k")

    local_reg = CapabilityRegistry()
    local_router = StaticRouter(routes={})
    local = Kernel(
        registry=local_reg,
        token_provider=HMACTokenProvider(secret="local-secret"),
        router=local_router,
        kernel_id="agent-a",
    )

    remote_driver = InMemoryDriver(driver_id="remote_b")
    remote_driver.register_handler(
        "billing.list_invoices",
        lambda ctx: [{"id": "INV-1", "amount": 10.0}],
    )

    imported = local.import_remote(manifest, driver=remote_driver, trust_policy="local_only")
    assert [c.capability_id for c in imported] == ["billing.list_invoices"]

    # The driver-routing wiring is correct.
    plan = local_router.route("billing.list_invoices")
    assert plan.driver_ids == ["remote_b"]


def test_import_remote_requires_mutable_router() -> None:
    """A router without add_route() cannot make imports routable — fail clean."""
    from agent_kernel import FederationError
    from agent_kernel.models import RoutePlan

    class _ReadOnlyRouter:
        """Conforms to the Router Protocol (route only); cannot accept new routes."""

        def route(self, capability_id: str) -> RoutePlan:  # pragma: no cover - never called
            raise NotImplementedError

    remote = _remote_kernel_with(_make_cap("billing.list_invoices"))
    manifest = remote.advertise(endpoint="https://agent-b/k")

    local_reg = CapabilityRegistry()
    local = Kernel(
        registry=local_reg,
        token_provider=HMACTokenProvider(secret="local-secret"),
        router=_ReadOnlyRouter(),
        kernel_id="agent-a",
    )
    driver = InMemoryDriver(driver_id="remote_b")
    with pytest.raises(FederationError, match="requires a router that supports add_route"):
        local.import_remote(manifest, driver=driver, trust_policy="local_only")
    # Failing clean: nothing imported or registered locally.
    assert local_reg.list_all() == []


def test_imported_capability_invokes_through_local_pipeline() -> None:
    remote = _remote_kernel_with(_make_cap("billing.list_invoices"))
    manifest = remote.advertise(endpoint="https://agent-b/k")

    local_reg = CapabilityRegistry()
    local = Kernel(
        registry=local_reg,
        token_provider=HMACTokenProvider(secret="local-secret"),
        router=StaticRouter(),
        kernel_id="agent-a",
    )
    driver = InMemoryDriver(driver_id="remote_b")
    invoked = {"called_with": None}

    def list_invoices(ctx: ExecutionContext) -> list[dict[str, object]]:
        invoked["called_with"] = ctx.capability_id  # type: ignore[assignment]
        return [{"id": "INV-1", "amount": 100.0, "email": "x@y.z"}]

    driver.register_handler("billing.list_invoices", list_invoices)
    local.import_remote(manifest, driver=driver, trust_policy="local_only")

    principal = Principal(principal_id="alice", roles=["reader"], attributes={"tenant": "acme"})
    request = CapabilityRequest(capability_id="billing.list_invoices", goal="check invoices")
    token = local.get_token(request, principal, justification="")

    async def run() -> object:
        return await local.invoke(
            token,
            principal=principal,
            args={"operation": "billing.list_invoices"},
            response_mode="table",
        )

    frame = asyncio.run(run())
    # Capability was routed to the imported driver.
    assert invoked["called_with"] == "billing.list_invoices"
    # Trace was recorded by the local kernel.
    trace = local.explain(frame.action_id)  # type: ignore[attr-defined]
    assert trace.capability_id == "billing.list_invoices"
    assert trace.driver_id == "remote_b"


def test_imported_capability_keeps_remote_sensitivity_under_most_restrictive() -> None:
    """A `most_restrictive` import floors the imported cap's sensitivity at the remote tag.

    This is what makes the firewall apply the same redaction to imported PII
    capabilities as the remote would.
    """
    remote = _remote_kernel_with(_make_cap("crm.contacts.list", sensitivity=SensitivityTag.PII))
    manifest = remote.advertise(endpoint="https://agent-b/k")
    local = Kernel(
        registry=CapabilityRegistry(),
        token_provider=HMACTokenProvider(secret="local-secret"),
        kernel_id="agent-a",
    )
    local.import_remote(manifest, driver=InMemoryDriver(driver_id="remote_b"))
    imported_cap = local.list_capabilities()[0]
    assert imported_cap.sensitivity == SensitivityTag.PII


# ── Token isolation across kernels (kernel-scoped HMAC) ───────────────────────


def test_tokens_are_kernel_scoped_by_hmac_secret() -> None:
    """A token signed by kernel A's HMAC provider must not verify on kernel B.

    `Kernel` instances with different secrets produce tokens that fail
    signature verification on the other side, which is what makes
    "kernel-scoped" tokens safe across an imported capability boundary.
    """
    reg_a = CapabilityRegistry()
    reg_a.register(_make_cap("billing.list_invoices"))
    kernel_a = Kernel(
        registry=reg_a,
        token_provider=HMACTokenProvider(secret="secret-a"),
        router=StaticRouter(),
        kernel_id="agent-a",
    )

    reg_b = CapabilityRegistry()
    reg_b.register(_make_cap("billing.list_invoices"))
    kernel_b_provider = HMACTokenProvider(secret="secret-b")

    principal = Principal(principal_id="alice", roles=["reader"], attributes={"tenant": "acme"})
    token = kernel_a.get_token(
        CapabilityRequest(capability_id="billing.list_invoices", goal="x"),
        principal,
        justification="",
    )
    with pytest.raises(TokenInvalid, match="invalid signature"):
        kernel_b_provider.verify(
            token,
            expected_principal_id="alice",
            expected_capability_id="billing.list_invoices",
        )
