"""Tests for KernelStats counters and kernel integration (issue #179)."""

from __future__ import annotations

import asyncio
import threading

import pytest

from weaver_kernel import (
    Kernel,
    KernelStats,
    PolicyDenied,
    Principal,
    StatsSnapshot,
)
from weaver_kernel.models import CapabilityRequest

# ── Unit: the collector ────────────────────────────────────────────────────────


def test_snapshot_is_immutable_copy() -> None:
    stats = KernelStats()
    stats.on_grant()
    snap = stats.snapshot()
    assert isinstance(snap, StatsSnapshot)
    stats.on_grant()  # mutating the live collector does not change the snapshot
    assert snap.grants == 1
    assert stats.snapshot().grants == 2


def test_denials_bucketed_by_reason_code() -> None:
    stats = KernelStats()
    stats.on_denial("missing_role")
    stats.on_denial("missing_role")
    stats.on_denial("rate_limited")
    stats.on_denial(None)  # unknown bucket
    snap = stats.snapshot()
    assert snap.denials == 4
    assert snap.denials_by_reason["missing_role"] == 2
    assert snap.denials_by_reason["rate_limited"] == 1
    assert snap.denials_by_reason["unknown"] == 1


def test_denials_by_reason_snapshot_is_read_only() -> None:
    stats = KernelStats()
    stats.on_denial("missing_role")
    snap = stats.snapshot()
    with pytest.raises(TypeError):
        snap.denials_by_reason["missing_role"] = 99  # type: ignore[index]


def test_on_invocation_flags() -> None:
    stats = KernelStats()
    stats.on_invocation(failed=False, fallback=True, redacted=True, downgraded=False)
    stats.on_invocation(failed=True, fallback=False, redacted=False, downgraded=True)
    snap = stats.snapshot()
    assert snap.invocations == 2
    assert snap.invocation_failures == 1
    assert snap.fallback_activations == 1
    assert snap.redaction_events == 1
    assert snap.budget_downgrades == 1


def test_reset_zeroes_all_counters() -> None:
    stats = KernelStats()
    stats.on_grant()
    stats.on_denial("missing_role")
    stats.on_expansion()
    stats.reset()
    snap = stats.snapshot()
    assert snap.grants == 0
    assert snap.denials == 0
    assert snap.expansions == 0
    assert dict(snap.denials_by_reason) == {}


def test_snapshot_safe_under_concurrent_increments() -> None:
    stats = KernelStats()
    workers = 8
    per_worker = 1000

    def hammer() -> None:
        for _ in range(per_worker):
            stats.on_grant()

    threads = [threading.Thread(target=hammer) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert stats.snapshot().grants == workers * per_worker


# ── Kernel integration ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_grant_invoke_expand_counts(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="list")
    grant = kernel.grant_capability(req, reader_principal, justification="audit")
    frame = await kernel.invoke(
        grant.token, principal=reader_principal, args={"operation": "billing.list_invoices"}
    )
    assert frame.handle is not None
    kernel.expand(frame.handle, query={"limit": 1}, principal=reader_principal)

    snap = kernel.stats
    assert snap.grants == 1
    assert snap.invocations == 1
    assert snap.handle_stores == 1
    assert snap.expansions == 1
    assert snap.denials == 0


def test_denied_grant_is_counted(kernel: Kernel, reader_principal: Principal) -> None:
    # A reader cannot be granted a DESTRUCTIVE capability.
    req = CapabilityRequest(capability_id="billing.delete_invoice", goal="delete")
    with pytest.raises(PolicyDenied):
        kernel.grant_capability(req, reader_principal, justification="nope")

    snap = kernel.stats
    assert snap.grants == 0
    assert snap.denials == 1
    assert sum(snap.denials_by_reason.values()) == 1


def test_reset_stats_via_kernel(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="list")
    kernel.grant_capability(req, reader_principal, justification="audit")
    assert kernel.stats.grants == 1
    kernel.reset_stats()
    assert kernel.stats.grants == 0


def test_redaction_event_counted_when_frame_warns() -> None:
    """An invocation whose Frame carries a redaction warning bumps the counter."""
    from weaver_kernel import (
        Capability,
        CapabilityRegistry,
        HMACTokenProvider,
        InMemoryDriver,
        SafetyClass,
        StaticRouter,
    )

    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="svc.lookup",
            name="lookup",
            description="lookup",
            safety_class=SafetyClass.READ,
        )
    )
    driver = InMemoryDriver(driver_id="svc")
    # An inline email triggers the firewall's redaction warning.
    driver.register_handler("svc.lookup", lambda _ctx: [{"note": "reach me at a@b.invalid"}])
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=StaticRouter(routes={"svc.lookup": ["svc"]}),
    )
    kernel.register_driver(driver)
    principal = Principal(principal_id="u1", roles=["reader"])
    req = CapabilityRequest(capability_id="svc.lookup", goal="lookup")
    grant = kernel.grant_capability(req, principal, justification="audit")
    frame = asyncio.run(
        kernel.invoke(grant.token, principal=principal, args={"operation": "svc.lookup"})
    )
    assert frame.warnings  # redaction happened
    assert kernel.stats.redaction_events == 1
