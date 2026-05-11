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


# ── Dry-run mode ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dry_run_returns_dry_run_result(kernel: Kernel, reader_principal: Principal) -> None:
    """dry_run=True returns DryRunResult, not Frame."""
    from agent_kernel.models import DryRunResult

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="test")
    token = kernel.get_token(req, reader_principal, justification="")
    result = await kernel.invoke(token, principal=reader_principal, args={}, dry_run=True)
    assert isinstance(result, DryRunResult)
    assert result.capability_id == "billing.list_invoices"
    assert result.principal_id == reader_principal.principal_id
    assert result.policy_decision.allowed is True
    assert result.budget_remaining is None


@pytest.mark.asyncio
async def test_dry_run_driver_not_called(
    kernel: Kernel, reader_principal: Principal, memory_driver: InMemoryDriver
) -> None:
    """Driver execute() must never be called in dry-run mode."""
    from unittest.mock import AsyncMock, patch

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="test")
    token = kernel.get_token(req, reader_principal, justification="")
    with patch.object(memory_driver, "execute", new_callable=AsyncMock) as mock_exec:
        await kernel.invoke(token, principal=reader_principal, args={}, dry_run=True)
        mock_exec.assert_not_called()


@pytest.mark.asyncio
async def test_dry_run_estimated_cost(kernel: Kernel, admin_principal: Principal) -> None:
    """estimated_cost maps to safety class."""
    from agent_kernel.models import DryRunResult

    read_req = CapabilityRequest(capability_id="billing.list_invoices", goal="r")
    read_token = kernel.get_token(read_req, admin_principal, justification="")
    read_result = await kernel.invoke(read_token, principal=admin_principal, args={}, dry_run=True)
    assert isinstance(read_result, DryRunResult)
    assert read_result.estimated_cost == "low"

    del_req = CapabilityRequest(capability_id="billing.delete_invoice", goal="d")
    del_token = kernel.get_token(
        del_req, admin_principal, justification="long enough justification here"
    )
    del_result = await kernel.invoke(del_token, principal=admin_principal, args={}, dry_run=True)
    assert isinstance(del_result, DryRunResult)
    assert del_result.estimated_cost == "high"


@pytest.mark.asyncio
async def test_dry_run_operation_uses_args_then_capability_id(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """Dry-run resolves ``operation`` the same way drivers do at real-invoke.

    Drivers read ``ctx.args.get("operation", ctx.capability_id)``. Dry-run
    must mirror that exactly so ``DryRunResult.operation`` matches what a
    driver would actually receive.
    """
    from agent_kernel.models import DryRunResult

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = kernel.get_token(req, reader_principal, justification="")

    # Explicit operation in args wins.
    explicit = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.custom_op"},
        dry_run=True,
    )
    assert isinstance(explicit, DryRunResult)
    assert explicit.operation == "billing.custom_op"

    # No operation in args → falls back to the capability_id (NOT impl.operation).
    fallback = await kernel.invoke(
        token,
        principal=reader_principal,
        args={},
        dry_run=True,
    )
    assert isinstance(fallback, DryRunResult)
    assert fallback.operation == "billing.list_invoices"


@pytest.mark.asyncio
async def test_dry_run_downgrades_raw_for_non_admin(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """Dry-run mirrors the Firewall's raw-mode admin gate.

    Non-admin principals never get raw mode at real-invoke
    (see firewall/transform.py); dry-run must downgrade too so callers
    cannot probe/assume raw availability they will never receive.
    """
    from agent_kernel.models import DryRunResult

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = kernel.get_token(req, reader_principal, justification="")
    result = await kernel.invoke(
        token,
        principal=reader_principal,
        args={},
        response_mode="raw",
        dry_run=True,
    )
    assert isinstance(result, DryRunResult)
    assert result.response_mode == "summary"


@pytest.mark.asyncio
async def test_dry_run_preserves_raw_for_admin(kernel: Kernel, admin_principal: Principal) -> None:
    """Admin principals keep raw mode in dry-run (no downgrade)."""
    from agent_kernel.models import DryRunResult

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = kernel.get_token(req, admin_principal, justification="")
    result = await kernel.invoke(
        token,
        principal=admin_principal,
        args={},
        response_mode="raw",
        dry_run=True,
    )
    assert isinstance(result, DryRunResult)
    assert result.response_mode == "raw"


@pytest.mark.asyncio
async def test_dry_run_expired_token_still_raises(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """Token expiry is enforced even in dry-run mode."""
    from agent_kernel import HMACTokenProvider, TokenExpired

    provider = HMACTokenProvider(secret="test-secret-do-not-use-in-prod")
    token = provider.issue(
        "billing.list_invoices",
        reader_principal.principal_id,
        constraints={},
        audit_id="audit-expired",
        ttl_seconds=-1,
    )
    with pytest.raises(TokenExpired):
        await kernel.invoke(token, principal=reader_principal, args={}, dry_run=True)


# ── explain_denial ─────────────────────────────────────────────────────────────


def test_explain_denial_allowed(kernel: Kernel, reader_principal: Principal) -> None:
    """explain_denial returns denied=False for an allowed request."""
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="test")
    result = kernel.explain_denial(req, reader_principal, justification="")
    assert result.denied is False
    assert result.failed_conditions == []


def test_explain_denial_write_no_role(kernel: Kernel, reader_principal: Principal) -> None:
    """explain_denial reports role failure for WRITE without writer role."""
    req = CapabilityRequest(capability_id="billing.update_invoice", goal="update")
    result = kernel.explain_denial(
        req, reader_principal, justification="long enough justification"
    )
    assert result.denied is True
    assert any(fc.condition == "roles" for fc in result.failed_conditions)


def test_explain_denial_write_short_justification(
    kernel: Kernel, writer_principal: Principal
) -> None:
    """explain_denial reports justification failure for WRITE with short justification."""
    req = CapabilityRequest(capability_id="billing.update_invoice", goal="update")
    result = kernel.explain_denial(req, writer_principal, justification="short")
    assert result.denied is True
    assert any(fc.condition == "min_justification" for fc in result.failed_conditions)


def test_explain_denial_capability_not_found(kernel: Kernel, reader_principal: Principal) -> None:
    """explain_denial raises CapabilityNotFound for unknown capability."""
    from agent_kernel import CapabilityNotFound

    req = CapabilityRequest(capability_id="nonexistent.capability", goal="test")
    with pytest.raises(CapabilityNotFound):
        kernel.explain_denial(req, reader_principal)


def test_explain_denial_engine_without_explain_raises(
    registry: CapabilityRegistry, reader_principal: Principal
) -> None:
    """A policy engine that only implements evaluate() surfaces a clear error.

    The ``PolicyEngine`` protocol requires only ``evaluate()``; engines that
    don't implement ``explain()`` raise ``AgentKernelError`` from
    ``Kernel.explain_denial`` rather than producing a misleading explanation.
    """
    from agent_kernel import AgentKernelError, PolicyDenied
    from agent_kernel.models import PolicyDecision

    class EvaluateOnlyEngine:
        """Minimal engine satisfying PolicyEngine but not ExplainingPolicyEngine."""

        def evaluate(
            self,
            request: CapabilityRequest,
            capability: Capability,
            principal: Principal,
            *,
            justification: str,
        ) -> PolicyDecision:
            raise PolicyDenied("denied for test")

    k = Kernel(
        registry=registry,
        policy=EvaluateOnlyEngine(),  # type: ignore[arg-type]
        token_provider=HMACTokenProvider(secret="test-secret"),
    )
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    with pytest.raises(AgentKernelError, match="does not implement explain"):
        k.explain_denial(req, reader_principal)
