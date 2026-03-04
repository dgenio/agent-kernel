"""Integration tests for the Kernel (full flow)."""

from __future__ import annotations

import pytest

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    DriverError,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    PolicyDenied,
    Principal,
    SafetyClass,
    StaticRouter,
    TokenExpired,
)
from agent_kernel.models import CapabilityRequest

# ── Full flow: request → grant → invoke → expand → explain ─────────────────────


@pytest.mark.asyncio
async def test_full_flow(kernel: Kernel, reader_principal: Principal) -> None:
    requests = kernel.request_capabilities("list invoices")
    assert len(requests) > 0

    req = CapabilityRequest(
        capability_id="billing.list_invoices",
        goal="list all invoices",
    )
    token = kernel.get_token(req, reader_principal, justification="")
    assert token.capability_id == "billing.list_invoices"

    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
    )
    assert frame.response_mode == "summary"
    assert frame.action_id != ""

    # explain
    trace = kernel.explain(frame.action_id)
    assert trace.capability_id == "billing.list_invoices"
    assert trace.principal_id == reader_principal.principal_id

    # expand
    assert frame.handle is not None
    expanded = kernel.expand(frame.handle, query={"offset": 0, "limit": 2})
    assert len(expanded.table_preview) <= 2


@pytest.mark.asyncio
async def test_invoke_table_mode(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="table")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="table",
    )
    assert frame.response_mode == "table"


@pytest.mark.asyncio
async def test_invoke_handle_only_mode(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="handle")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="handle_only",
    )
    assert frame.response_mode == "handle_only"
    assert frame.handle is not None


# ── Denial flow ────────────────────────────────────────────────────────────────


def test_grant_denied_write_no_role(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(
        capability_id="billing.update_invoice",
        goal="update invoice",
    )
    with pytest.raises(PolicyDenied):
        kernel.get_token(req, reader_principal, justification="long enough justification here")


def test_grant_denied_destructive_no_admin(kernel: Kernel, writer_principal: Principal) -> None:
    req = CapabilityRequest(
        capability_id="billing.delete_invoice",
        goal="delete invoice",
    )
    with pytest.raises(PolicyDenied):
        kernel.get_token(req, writer_principal, justification="long enough justification here")


def test_grant_allowed_write_writer_role(kernel: Kernel, writer_principal: Principal) -> None:
    req = CapabilityRequest(
        capability_id="billing.update_invoice",
        goal="update invoice",
    )
    token = kernel.get_token(
        req, writer_principal, justification="this is a long enough justification"
    )
    assert token.capability_id == "billing.update_invoice"


# ── Expired token flow ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invoke_expired_token(kernel: Kernel, reader_principal: Principal) -> None:
    token_provider = HMACTokenProvider(secret="test-secret-do-not-use-in-prod")
    token = token_provider.issue(
        "billing.list_invoices",
        reader_principal.principal_id,
        ttl_seconds=-1,
    )
    with pytest.raises(TokenExpired):
        await kernel.invoke(
            token,
            principal=reader_principal,
            args={"operation": "billing.list_invoices"},
        )


# ── Fallback driver flow ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fallback_driver_flow() -> None:
    """If the first driver fails, the kernel tries the next one."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="test.cap",
            name="Test",
            description="Test capability",
            safety_class=SafetyClass.READ,
        )
    )

    primary = InMemoryDriver(driver_id="primary")
    # primary raises DriverError
    primary.register_handler(
        "test.cap", lambda ctx: (_ for _ in ()).throw(DriverError("primary fail"))
    )

    fallback = InMemoryDriver(driver_id="fallback")
    fallback.register_handler("test.cap", lambda ctx: {"from": "fallback"})

    router = StaticRouter(routes={"test.cap": ["primary", "fallback"]})
    token_provider = HMACTokenProvider(secret="test-secret")
    k = Kernel(registry=registry, router=router, token_provider=token_provider)
    k.register_driver(primary)
    k.register_driver(fallback)

    principal = Principal(principal_id="u1")
    token = token_provider.issue("test.cap", "u1")
    frame = await k.invoke(token, principal=principal, args={})
    assert frame.response_mode == "summary"
    trace = k.explain(frame.action_id)
    assert trace.driver_id == "fallback"


@pytest.mark.asyncio
async def test_all_drivers_fail_raises_driver_error() -> None:
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="test.fail",
            name="Fail",
            description="Always fails",
            safety_class=SafetyClass.READ,
        )
    )
    bad_driver = InMemoryDriver(driver_id="bad")
    bad_driver.register_handler(
        "test.fail", lambda ctx: (_ for _ in ()).throw(DriverError("always fail"))
    )

    router = StaticRouter(routes={"test.fail": ["bad"]})
    token_provider = HMACTokenProvider(secret="test-secret")
    k = Kernel(registry=registry, router=router, token_provider=token_provider)
    k.register_driver(bad_driver)

    principal = Principal(principal_id="u1")
    token = token_provider.issue("test.fail", "u1")
    with pytest.raises(DriverError):
        await k.invoke(token, principal=principal, args={})


# ── Confused-deputy prevention ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_confused_deputy_prevention(kernel: Kernel, reader_principal: Principal) -> None:
    """A token issued for one principal cannot be used by another."""
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="test")
    token = kernel.get_token(req, reader_principal, justification="")

    other_principal = Principal(principal_id="attacker-999", roles=["reader"])
    from agent_kernel import TokenScopeError

    with pytest.raises(TokenScopeError):
        await kernel.invoke(
            token,
            principal=other_principal,
            args={"operation": "billing.list_invoices"},
        )
