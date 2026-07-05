"""Integration tests for the Kernel (full flow)."""

from __future__ import annotations

import asyncio

import pytest

from weaver_kernel import (
    BudgetManager,
    Capability,
    CapabilityRegistry,
    DriverError,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    PolicyDenied,
    Principal,
    RateLimiter,
    RateLimitExceeded,
    SafetyClass,
    StaticRouter,
    TokenExpired,
    TokenInvalid,
    TokenScopeError,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.errors import FirewallError
from weaver_kernel.firewall.transform import Firewall
from weaver_kernel.models import CapabilityRequest, RawResult

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
    expanded = kernel.expand(
        frame.handle, query={"offset": 0, "limit": 2}, principal=reader_principal
    )
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


@pytest.mark.asyncio
async def test_trace_records_result_summary(kernel: Kernel, reader_principal: Principal) -> None:
    """A successful invocation records a redaction-safe result summary.

    The summary is derived from the firewalled Frame (counts/flags only), so the
    invocation's outcome is auditable directly from ``explain`` without
    re-introducing raw driver data.
    """
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="summary")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="table",
    )
    trace = kernel.explain(frame.action_id)
    assert trace.result_summary is not None
    assert set(trace.result_summary) == {
        "fact_count",
        "row_count",
        "warning_count",
        "has_handle",
    }
    # Counts mirror the firewalled Frame the caller received.
    assert trace.result_summary["row_count"] == len(frame.table_preview)
    assert trace.result_summary["has_handle"] == (frame.handle is not None)


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


# ── Fail-closed driver execution: audit + budget release (#152, #191) ──────────


class _RawRaisingDriver:
    """A driver whose ``execute`` raises a non-DriverError (e.g. a library bug)."""

    def __init__(self, driver_id: str = "raw_raiser") -> None:
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        raise ValueError("unexpected library failure")


class _SlowDriver:
    """A driver that sleeps past any reasonable per-invocation deadline."""

    def __init__(self, driver_id: str = "slow") -> None:
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        await asyncio.sleep(1.0)
        return RawResult(capability_id=ctx.capability_id, data="late")


class _BoomFirewall(Firewall):
    """A Firewall whose ``transform`` always fails — to exercise the post-driver path."""

    def transform(self, *args: object, **kwargs: object):  # type: ignore[override]
        raise FirewallError("transform boom")


def _single_driver_kernel(
    driver: object,
    *,
    budget: int | None = None,
    invoke_rate_limits: dict[SafetyClass, tuple[int, float]] | None = None,
    invoke_rate_limiter: RateLimiter | None = None,
) -> Kernel:
    """Build a kernel routing ``cap`` to *driver*, optionally with a budget
    and/or invoke-time rate limiting (#170)."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="cap",
            name="Cap",
            description="A capability under test",
            safety_class=SafetyClass.READ,
        )
    )
    return Kernel(
        registry=registry,
        router=StaticRouter(routes={"cap": [driver.driver_id]}),  # type: ignore[attr-defined]
        token_provider=HMACTokenProvider(secret="test-secret"),
        budget_manager=BudgetManager(total_budget=budget) if budget is not None else None,
        invoke_rate_limits=invoke_rate_limits,
        invoke_rate_limiter=invoke_rate_limiter,
    )


@pytest.mark.asyncio
async def test_non_driver_error_is_audited_and_budget_released() -> None:
    """A driver raising a non-DriverError is audited and the reservation freed (#152)."""
    driver = _RawRaisingDriver()
    k = _single_driver_kernel(driver, budget=10_000)
    k.register_driver(driver)
    assert k.budget is not None
    before = k.budget.remaining

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")
    with pytest.raises(DriverError, match="All drivers failed"):
        await k.invoke(token, principal=principal, args={})

    # Budget reservation released (no leak), and a failure trace was recorded
    # attributing the last-attempted driver (#152).
    assert k.budget.remaining == before
    traces = k.list_traces()
    assert len(traces) == 1
    assert traces[0].driver_id == "raw_raiser"
    assert "unexpected library failure" in (traces[0].error or "")


@pytest.mark.asyncio
async def test_firewall_failure_is_audited_and_budget_released() -> None:
    """A post-driver firewall failure is audited and the reservation freed (#152)."""
    driver = InMemoryDriver(driver_id="ok")
    driver.register_handler("cap", lambda ctx: {"value": 1})
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="cap",
            name="Cap",
            description="A capability under test",
            safety_class=SafetyClass.READ,
        )
    )
    k = Kernel(
        registry=registry,
        router=StaticRouter(routes={"cap": ["ok"]}),
        token_provider=HMACTokenProvider(secret="test-secret"),
        firewall=_BoomFirewall(),
        budget_manager=BudgetManager(total_budget=10_000),
    )
    k.register_driver(driver)
    assert k.budget is not None
    before = k.budget.remaining

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")
    with pytest.raises(FirewallError, match="transform boom"):
        await k.invoke(token, principal=principal, args={})

    assert k.budget.remaining == before
    traces = k.list_traces()
    assert len(traces) == 1
    assert "transform boom" in (traces[0].error or "")


@pytest.mark.asyncio
async def test_invoke_timeout_constraint_aborts_slow_driver() -> None:
    """A per-grant ``invoke_timeout_s`` constraint bounds execution (#191)."""
    driver = _SlowDriver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1", constraints={"invoke_timeout_s": 0.01})
    with pytest.raises(DriverError, match="timed out after 0.01s"):
        await k.invoke(token, principal=principal, args={})

    traces = k.list_traces()
    assert len(traces) == 1
    assert "timed out" in (traces[0].error or "")


@pytest.mark.asyncio
async def test_invalid_invoke_timeout_constraint_rejected() -> None:
    """A malformed ``invoke_timeout_s`` constraint fails fast with a typed error (#191)."""
    driver = InMemoryDriver(driver_id="ok")
    driver.register_handler("cap", lambda ctx: {"value": 1})
    k = _single_driver_kernel(driver)
    k.register_driver(driver)

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1", constraints={"invoke_timeout_s": -5})
    with pytest.raises(DriverError, match="invoke_timeout_s"):
        await k.invoke(token, principal=principal, args={})


@pytest.mark.asyncio
async def test_cancellation_is_audited_and_budget_released() -> None:
    """Cancelling an in-flight invoke releases the reservation and is audited (#152)."""
    driver = _SlowDriver()
    k = _single_driver_kernel(driver, budget=10_000)
    k.register_driver(driver)
    assert k.budget is not None
    before = k.budget.remaining

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")
    task = asyncio.create_task(k.invoke(token, principal=principal, args={}))
    await asyncio.sleep(0.05)  # let the task reach the (slow) driver
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        # Awaiting the cancelled task re-raises CancelledError — that *is* the
        # effect under test (assigned to ``_`` so static analysis sees it).
        _ = await task

    assert k.budget.remaining == before
    traces = k.list_traces()
    assert len(traces) == 1
    assert "cancelled" in (traces[0].error or "")


@pytest.mark.asyncio
async def test_stream_timeout_records_error_reason() -> None:
    """A streaming timeout records the real failure reason, not a generic note (#191)."""
    driver = _SlowDriver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)

    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1", constraints={"invoke_timeout_s": 0.01})
    with pytest.raises(DriverError, match="timed out"):
        async for _ in k.invoke_stream(token, principal=principal, args={}):
            pass

    traces = k.list_traces()
    assert len(traces) == 1
    assert "timed out" in (traces[0].error or "")


# ── Invoke-time rate limiting (#170) ─────────────────────────────────────────


def _ok_driver() -> InMemoryDriver:
    driver = InMemoryDriver(driver_id="ok")
    driver.register_handler("cap", lambda ctx: {"value": 1})
    return driver


@pytest.mark.asyncio
async def test_invoke_rate_limit_disabled_by_default() -> None:
    """Without invoke_rate_limits configured, invoke() has no per-call limit."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")
    for _ in range(100):
        await k.invoke(token, principal=principal, args={})  # never raises


@pytest.mark.asyncio
async def test_invoke_rate_limit_denies_after_window_exceeded() -> None:
    """Repeated invoke() on one token is denied once the window limit is hit (#170)."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver, invoke_rate_limits={SafetyClass.READ: (2, 60.0)})
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")

    await k.invoke(token, principal=principal, args={})
    await k.invoke(token, principal=principal, args={})
    with pytest.raises(RateLimitExceeded) as exc_info:
        await k.invoke(token, principal=principal, args={})
    assert exc_info.value.reason_code == "invoke_rate_limited"


@pytest.mark.asyncio
async def test_invoke_rate_limit_records_deny_trace() -> None:
    """A rate-limited invocation still produces an audited ``"deny"`` trace (I-02)."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver, invoke_rate_limits={SafetyClass.READ: (1, 60.0)})
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")

    await k.invoke(token, principal=principal, args={})
    with pytest.raises(RateLimitExceeded):
        await k.invoke(token, principal=principal, args={})

    deny_traces = [t for t in k.list_traces() if t.event_type == "deny"]
    assert len(deny_traces) == 1
    assert deny_traces[0].reason_code == "invoke_rate_limited"


@pytest.mark.asyncio
async def test_invoke_rate_limit_window_resets() -> None:
    """The window slides: an invocation succeeds again once it elapses."""
    time_ref = [0.0]
    limiter = RateLimiter(clock=lambda: time_ref[0])
    driver = _ok_driver()
    k = _single_driver_kernel(
        driver,
        invoke_rate_limits={SafetyClass.READ: (1, 10.0)},
        invoke_rate_limiter=limiter,
    )
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")

    await k.invoke(token, principal=principal, args={})
    with pytest.raises(RateLimitExceeded):
        await k.invoke(token, principal=principal, args={})

    time_ref[0] = 11.0  # advance past the 10s window
    await k.invoke(token, principal=principal, args={})  # succeeds again


@pytest.mark.asyncio
async def test_invoke_rate_limit_dry_run_does_not_consume() -> None:
    """A dry-run never counts against the invoke-time rate limit (#170)."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver, invoke_rate_limits={SafetyClass.READ: (1, 60.0)})
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")

    for _ in range(5):
        await k.invoke(token, principal=principal, args={}, dry_run=True)
    # The real limit (1) is still fully available after five dry-runs.
    await k.invoke(token, principal=principal, args={})
    with pytest.raises(RateLimitExceeded):
        await k.invoke(token, principal=principal, args={})


@pytest.mark.asyncio
async def test_invoke_rate_limit_scoped_per_principal_and_capability() -> None:
    """The limit is keyed by (principal_id, capability_id), not global."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver, invoke_rate_limits={SafetyClass.READ: (1, 60.0)})
    k.register_driver(driver)
    token_u1 = k._token_provider.issue("cap", "u1")
    token_u2 = k._token_provider.issue("cap", "u2")

    await k.invoke(token_u1, principal=Principal(principal_id="u1"), args={})
    with pytest.raises(RateLimitExceeded):
        await k.invoke(token_u1, principal=Principal(principal_id="u1"), args={})
    # u2's own limit is untouched.
    await k.invoke(token_u2, principal=Principal(principal_id="u2"), args={})


@pytest.mark.asyncio
async def test_invoke_rate_limit_concurrent_calls_do_not_exceed_limit() -> None:
    """Concurrent invoke() calls near the limit boundary never over-admit (no
    check-then-record race): exactly `limit` of N concurrent calls succeed."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver, invoke_rate_limits={SafetyClass.READ: (3, 60.0)})
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue("cap", "u1")

    results = await asyncio.gather(
        *[k.invoke(token, principal=principal, args={}) for _ in range(10)],
        return_exceptions=True,
    )
    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, RateLimitExceeded)]
    assert len(successes) == 3
    assert len(failures) == 7


# ── Signed argument-level constraints (#183) ─────────────────────────────────


@pytest.mark.asyncio
async def test_arg_constraint_allowed_keys_violation_denied() -> None:
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    with pytest.raises(TokenScopeError) as exc_info:
        await k.invoke(token, principal=principal, args={"safe_key": 1, "extra": 2})
    assert exc_info.value.reason_code == "arg_constraint_violation"


@pytest.mark.asyncio
async def test_arg_constraint_allowed_args_pass_through() -> None:
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    frame = await k.invoke(token, principal=principal, args={"safe_key": 1})
    assert frame.action_id != ""


@pytest.mark.asyncio
async def test_arg_constraint_pinned_violation_denied() -> None:
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"pinned": {"path": "/safe/x"}}}
    )
    with pytest.raises(TokenScopeError, match="pinned"):
        await k.invoke(token, principal=principal, args={"path": "/etc/passwd"})


@pytest.mark.asyncio
async def test_arg_constraint_prefix_violation_denied() -> None:
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"prefix": {"path": "/safe/"}}}
    )
    with pytest.raises(TokenScopeError, match="prefix"):
        await k.invoke(token, principal=principal, args={"path": "/etc/passwd"})


@pytest.mark.asyncio
async def test_arg_constraint_violation_never_reaches_driver() -> None:
    """A violating invoke is denied before the driver executes at all."""

    class _CountingDriver(InMemoryDriver):
        def __init__(self) -> None:
            super().__init__(driver_id="ok")
            self.calls = 0
            self.register_handler("cap", self._handle)

        def _handle(self, ctx: ExecutionContext) -> dict[str, int]:
            self.calls += 1
            return {"value": 1}

    driver = _CountingDriver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    with pytest.raises(TokenScopeError):
        await k.invoke(token, principal=principal, args={"extra": 1})
    assert driver.calls == 0


@pytest.mark.asyncio
async def test_arg_constraint_records_deny_trace_with_reason_code() -> None:
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    with pytest.raises(TokenScopeError):
        await k.invoke(token, principal=principal, args={"extra": 1})

    deny_traces = [t for t in k.list_traces() if t.event_type == "deny"]
    assert len(deny_traces) == 1
    assert deny_traces[0].reason_code == "arg_constraint_violation"


@pytest.mark.asyncio
async def test_arg_constraint_dry_run_predicts_same_denial() -> None:
    """Dry-run raises the identical error a real invoke would (#183)."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    with pytest.raises(TokenScopeError, match="extra"):
        await k.invoke(token, principal=principal, args={"extra": 1}, dry_run=True)


@pytest.mark.asyncio
async def test_arg_constraint_tampering_invalidates_signature() -> None:
    """Mutating a live token's args constraint invalidates its HMAC (I-06)."""
    driver = _ok_driver()
    k = _single_driver_kernel(driver)
    k.register_driver(driver)
    principal = Principal(principal_id="u1")
    token = k._token_provider.issue(
        "cap", "u1", constraints={"args": {"allowed_keys": ["safe_key"]}}
    )
    token.constraints["args"]["allowed_keys"] = ["anything"]  # tamper post-issuance
    with pytest.raises(TokenInvalid):
        await k.invoke(token, principal=principal, args={"anything": 1})


def test_validate_arg_constraints_pinned_match_passes() -> None:
    from weaver_kernel.kernel._arg_constraints import validate_arg_constraints

    validate_arg_constraints({"args": {"pinned": {"path": "/safe/x"}}}, {"path": "/safe/x"})


def test_validate_arg_constraints_prefix_match_passes() -> None:
    from weaver_kernel.kernel._arg_constraints import validate_arg_constraints

    validate_arg_constraints({"args": {"prefix": {"path": "/safe/"}}}, {"path": "/safe/file.txt"})


def test_validate_arg_constraints_prefix_non_string_value_denied() -> None:
    from weaver_kernel.kernel._arg_constraints import validate_arg_constraints

    with pytest.raises(TokenScopeError, match="must be a string"):
        validate_arg_constraints({"args": {"prefix": {"count": "/safe/"}}}, {"count": 42})


# ── Confused-deputy prevention ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_confused_deputy_prevention(kernel: Kernel, reader_principal: Principal) -> None:
    """A token issued for one principal cannot be used by another."""
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="test")
    token = kernel.get_token(req, reader_principal, justification="")

    other_principal = Principal(principal_id="attacker-999", roles=["reader"])
    from weaver_kernel import TokenScopeError

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
    from weaver_kernel.models import DryRunResult

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
    from weaver_kernel.models import DryRunResult

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
    from weaver_kernel.models import DryRunResult

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
    from weaver_kernel.models import DryRunResult

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
    from weaver_kernel.models import DryRunResult

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
    from weaver_kernel import HMACTokenProvider, TokenExpired

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
    from weaver_kernel import CapabilityNotFound

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
    from weaver_kernel import AgentKernelError, PolicyDenied
    from weaver_kernel.models import PolicyDecision

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


# ── Cross-invocation budget manager (#44) ─────────────────────────────────────


def _kernel_with_budget(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    *,
    total_budget: int,
    default_request: int = 4_000,
) -> Kernel:
    """Helper: construct a kernel wired with a BudgetManager."""
    from weaver_kernel import BudgetManager

    router = StaticRouter(
        routes={
            "billing.list_invoices": ["memory"],
            "billing.get_invoice": ["memory"],
            "billing.summarize_spend": ["memory"],
            "billing.update_invoice": ["memory"],
            "billing.delete_invoice": ["memory"],
        }
    )
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        budget_manager=BudgetManager(
            total_budget=total_budget,
            default_request=default_request,
        ),
    )
    k.register_driver(memory_driver)
    return k


@pytest.mark.asyncio
async def test_budget_manager_records_usage_across_invocations(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """Each invocation must move ``remaining`` strictly downward."""
    k = _kernel_with_budget(registry, memory_driver, total_budget=10_000)
    assert k.budget is not None

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")

    initial = k.budget.remaining
    await k.invoke(token, principal=reader_principal, args={"operation": "billing.list_invoices"})
    after_first = k.budget.remaining
    assert after_first < initial
    assert k.budget.used > 0

    # A second invocation consumes more.
    await k.invoke(token, principal=reader_principal, args={"operation": "billing.list_invoices"})
    after_second = k.budget.remaining
    assert after_second < after_first


@pytest.mark.asyncio
async def test_budget_manager_escalates_mode_when_remaining_under_five_percent(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """When remaining drops below 5%, even ``summary`` escalates to ``handle_only``."""
    from weaver_kernel import BudgetManager

    router = StaticRouter(routes={"billing.list_invoices": ["memory"]})
    bm = BudgetManager(total_budget=1000)
    # Pre-consume to push remaining under 5% before the invoke.
    await bm.record_usage(980)
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        budget_manager=bm,
    )
    k.register_driver(memory_driver)

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    frame = await k.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="summary",
    )
    assert frame.response_mode == "handle_only"


@pytest.mark.asyncio
async def test_budget_manager_exhausted_raises_before_driver_runs(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """An exhausted budget surfaces ``BudgetExhausted`` and skips the driver."""
    from weaver_kernel import BudgetExhausted, BudgetManager

    router = StaticRouter(routes={"billing.list_invoices": ["memory"]})
    bm = BudgetManager(total_budget=100)
    await bm.record_usage(100)  # Drive remaining to 0.
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        budget_manager=bm,
    )
    k.register_driver(memory_driver)

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    with pytest.raises(BudgetExhausted, match="Session budget exhausted"):
        await k.invoke(
            token,
            principal=reader_principal,
            args={"operation": "billing.list_invoices"},
        )


@pytest.mark.asyncio
async def test_budget_manager_releases_reservation_on_driver_failure(
    registry: CapabilityRegistry,
    reader_principal: Principal,
) -> None:
    """When all drivers fail, the reserved tokens must return to the pool."""
    from weaver_kernel import BudgetManager

    # Construct a kernel with a router pointing at a driver that does not exist.
    router = StaticRouter(routes={"billing.list_invoices": ["nope"]})
    bm = BudgetManager(total_budget=1000, default_request=200)
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        budget_manager=bm,
    )

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    with pytest.raises(DriverError):
        await k.invoke(
            token,
            principal=reader_principal,
            args={"operation": "billing.list_invoices"},
        )
    # Budget was reserved then released — nothing committed.
    assert bm.remaining == 1000
    assert bm.used == 0


@pytest.mark.asyncio
async def test_dry_run_reports_budget_remaining_when_manager_configured(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """DryRunResult.budget_remaining is populated when a BudgetManager is wired."""
    from weaver_kernel.models import DryRunResult

    k = _kernel_with_budget(registry, memory_driver, total_budget=10_000)
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    result = await k.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        dry_run=True,
    )
    assert isinstance(result, DryRunResult)
    assert result.budget_remaining == 10_000  # Dry-run does not commit.


@pytest.mark.asyncio
async def test_dry_run_reflects_escalated_mode_under_budget_pressure(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """Dry-run mirrors the BudgetManager escalation that a real invoke would apply."""
    from weaver_kernel import BudgetManager
    from weaver_kernel.models import DryRunResult

    router = StaticRouter(routes={"billing.list_invoices": ["memory"]})
    bm = BudgetManager(total_budget=1000)
    await bm.record_usage(980)  # < 5% remaining.
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        budget_manager=bm,
    )
    k.register_driver(memory_driver)

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    result = await k.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="table",
        dry_run=True,
    )
    assert isinstance(result, DryRunResult)
    assert result.response_mode == "handle_only"


@pytest.mark.asyncio
async def test_budget_manager_releases_reservation_on_firewall_failure(
    registry: CapabilityRegistry,
    memory_driver: InMemoryDriver,
    reader_principal: Principal,
) -> None:
    """Firewall raising after a reservation must release tokens to the pool.

    Without the finally block the reservation would stay locked, permanently
    eroding the cumulative budget on every transform failure.
    """
    from weaver_kernel import BudgetManager, FirewallError

    class FailingFirewall:
        def transform(self, *args: object, **kwargs: object) -> object:
            raise FirewallError("simulated firewall failure")

    router = StaticRouter(routes={"billing.list_invoices": ["memory"]})
    bm = BudgetManager(total_budget=1000, default_request=200)
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        firewall=FailingFirewall(),  # type: ignore[arg-type]
        budget_manager=bm,
    )
    k.register_driver(memory_driver)

    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = k.get_token(req, reader_principal, justification="")
    with pytest.raises(FirewallError, match="simulated firewall failure"):
        await k.invoke(
            token,
            principal=reader_principal,
            args={"operation": "billing.list_invoices"},
        )
    # Reservation was released; nothing committed because the frame never landed.
    assert bm.remaining == 1000
    assert bm.used == 0


@pytest.mark.asyncio
async def test_non_admin_raw_request_receives_handle_and_downgraded_frame(
    kernel: Kernel,
    reader_principal: Principal,
) -> None:
    """A non-admin asking for ``raw`` must get a handle + a non-raw frame.

    Before the admin-gate fix the kernel left ``effective_mode == "raw"``,
    skipped handle creation, and the firewall then downgraded to summary —
    yielding a summary frame *without* a handle. The fix mirrors the
    Firewall's admin gate inside the kernel so the handle is always stored.
    """
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
        response_mode="raw",
    )
    assert frame.response_mode != "raw"  # downgraded
    assert frame.handle is not None  # handle was stored despite the raw request


@pytest.mark.asyncio
async def test_kernel_without_budget_manager_behaves_identically(
    kernel: Kernel,
    reader_principal: Principal,
) -> None:
    """Backward-compat: the default kernel has ``kernel.budget is None``."""
    assert kernel.budget is None
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="t")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=reader_principal,
        args={"operation": "billing.list_invoices"},
    )
    # No escalation happens — requested mode flows through.
    assert frame.response_mode == "summary"


# ═══════════════════════════════════════════════════════════════════════════════
# Intent / scope, reason codes, and decision trace through the Kernel — #72/#73/#77
# ═══════════════════════════════════════════════════════════════════════════════


def test_explain_denial_surfaces_reason_code(kernel: Kernel, reader_principal: Principal) -> None:
    """Kernel.explain_denial forwards the engine's reason_code."""
    from weaver_kernel import DenialReason

    result = kernel.explain_denial(
        CapabilityRequest(capability_id="billing.update_invoice", goal="write"),
        reader_principal,
        justification="long enough justification here",
    )
    # billing.update_invoice is WRITE in conftest; reader has no writer role.
    assert result.denied is True
    assert result.reason_code == DenialReason.MISSING_ROLE


def test_grant_capability_carries_intent_through_request(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """A request with intent/scope should be accepted end-to-end and reach the decision trace."""
    from weaver_kernel import AllowReason

    req = CapabilityRequest(
        capability_id="billing.get_invoice",
        goal="lookup",
        intent="customer_support_lookup",
        scope={"region": "eu-west"},
    )
    grant = kernel.grant_capability(req, reader_principal, justification="")
    assert grant.decision.allowed is True
    assert grant.decision.reason_code == AllowReason.DEFAULT_POLICY_ALLOW
    assert grant.decision.trace is not None
    assert grant.decision.trace.intent == "customer_support_lookup"
    assert grant.decision.trace.scope_keys == ["region"]


@pytest.mark.asyncio
async def test_dry_run_policy_decision_has_trace(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """DryRunResult.policy_decision now carries a synthesized trace.

    The original grant-time decision was discarded with the request; the
    kernel emits a single-step ``token_verified`` trace so dry-run consumers
    can rely on a uniformly-shaped trace field.
    """
    from weaver_kernel.models import DryRunResult

    token = kernel.get_token(
        CapabilityRequest(capability_id="billing.get_invoice", goal="read"),
        reader_principal,
        justification="",
    )
    result = await kernel.invoke(token, principal=reader_principal, args={}, dry_run=True)
    assert isinstance(result, DryRunResult)
    assert result.policy_decision.trace is not None
    assert result.policy_decision.trace.engine == "Kernel.invoke[dry_run]"
    assert result.policy_decision.trace.final_outcome == "allowed"
    assert result.policy_decision.trace.final_reason_code == "token_verified"
    assert result.policy_decision.reason_code == "token_verified"


# ── Dry-run with HTTP and MCP drivers (issue #68 part E) ───────────────────────


@pytest.mark.asyncio
async def test_dry_run_with_http_driver_does_not_call_execute() -> None:
    """Dry-run short-circuits before driver dispatch — HTTPDriver edition.

    The short-circuit at ``kernel.invoke`` runs before driver lookup, so
    the mode is provably driver-agnostic. This test pins the contract so
    a future refactor that moved driver dispatch above the dry-run check
    cannot land unnoticed (per issue #68 part E acceptance criteria).
    """
    from unittest.mock import AsyncMock, patch

    from weaver_kernel.drivers.http import HTTPDriver, HTTPEndpoint
    from weaver_kernel.models import DryRunResult

    cap = Capability(
        capability_id="external.fetch_user",
        name="fetch_user",
        description="Fetch user from external HTTP API.",
        safety_class=SafetyClass.READ,
    )
    registry = CapabilityRegistry()
    registry.register(cap)

    http_driver = HTTPDriver(driver_id="http")
    http_driver.register_endpoint(
        "external.fetch_user",
        HTTPEndpoint(method="GET", url="https://example.invalid/u/1"),
    )

    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=StaticRouter(routes={"external.fetch_user": ["http"]}),
    )
    kernel.register_driver(http_driver)

    principal = Principal(principal_id="alice", roles=["reader"])
    req = CapabilityRequest(capability_id="external.fetch_user", goal="t")
    token = kernel.get_token(req, principal, justification="")

    with patch.object(http_driver, "execute", new_callable=AsyncMock) as mock_exec:
        result = await kernel.invoke(token, principal=principal, args={}, dry_run=True)
        mock_exec.assert_not_called()

    assert isinstance(result, DryRunResult)
    assert result.driver_id == "http"
    assert result.operation == "external.fetch_user"
    assert result.capability_id == "external.fetch_user"
    assert result.policy_decision.allowed is True


@pytest.mark.asyncio
async def test_dry_run_with_mcp_driver_does_not_call_execute() -> None:
    """Dry-run short-circuits before driver dispatch — MCPDriver edition.

    MCPDriver is constructed with a stub session factory so we never
    open a real subprocess or HTTP connection. The assertion is that
    ``execute`` is never called regardless — the short-circuit happens
    before the kernel looks up which driver to dispatch to.
    """
    from unittest.mock import AsyncMock, patch

    from weaver_kernel.drivers.mcp import MCPDriver
    from weaver_kernel.models import DryRunResult

    cap = Capability(
        capability_id="mcp.echo",
        name="echo",
        description="Echo tool from an MCP server.",
        safety_class=SafetyClass.READ,
    )
    registry = CapabilityRegistry()
    registry.register(cap)

    # Stub session factory — never invoked by dry-run.
    def _fake_session_factory() -> object:  # pragma: no cover - never called
        raise AssertionError("session_factory must not run during dry-run")

    mcp_driver = MCPDriver(
        driver_id="mcp:test",
        session_factory=_fake_session_factory,  # type: ignore[arg-type]
        server_name="test",
        transport="stdio",
    )

    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=StaticRouter(routes={"mcp.echo": ["mcp:test"]}),
    )
    kernel.register_driver(mcp_driver)

    principal = Principal(principal_id="alice", roles=["reader"])
    req = CapabilityRequest(capability_id="mcp.echo", goal="t")
    token = kernel.get_token(req, principal, justification="")

    with patch.object(mcp_driver, "execute", new_callable=AsyncMock) as mock_exec:
        result = await kernel.invoke(token, principal=principal, args={}, dry_run=True)
        mock_exec.assert_not_called()

    assert isinstance(result, DryRunResult)
    assert result.driver_id == "mcp:test"
    assert result.operation == "mcp.echo"
    assert result.capability_id == "mcp.echo"
    assert result.policy_decision.allowed is True


# ── Audit recording for denials and expansions (issue #175) ────────────────────


def test_denied_grant_records_deny_trace(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.delete_invoice", goal="delete")
    with pytest.raises(PolicyDenied):
        kernel.grant_capability(req, reader_principal, justification="nope")
    deny_traces = [t for t in kernel.list_traces() if t.event_type == "deny"]
    assert len(deny_traces) == 1
    assert deny_traces[0].capability_id == "billing.delete_invoice"
    assert deny_traces[0].principal_id == reader_principal.principal_id
    assert deny_traces[0].reason_code is not None
    # Retrievable via explain().
    assert kernel.explain(deny_traces[0].action_id).event_type == "deny"


@pytest.mark.asyncio
async def test_expand_records_expand_trace(kernel: Kernel, reader_principal: Principal) -> None:
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="list")
    token = kernel.get_token(req, reader_principal, justification="")
    frame = await kernel.invoke(
        token, principal=reader_principal, args={"operation": "billing.list_invoices"}
    )
    assert frame.handle is not None
    expanded = kernel.expand(frame.handle, query={"limit": 1}, principal=reader_principal)
    assert expanded.provenance.principal_id == reader_principal.principal_id

    expand_traces = [t for t in kernel.list_traces() if t.event_type == "expand"]
    assert len(expand_traces) == 1
    assert expand_traces[0].principal_id == reader_principal.principal_id
    assert expand_traces[0].handle_id == frame.handle.handle_id
    assert expand_traces[0].capability_id == "billing.list_invoices"


def test_kernel_query_traces(kernel: Kernel, reader_principal: Principal) -> None:
    from weaver_kernel import TraceQuery

    req = CapabilityRequest(capability_id="billing.delete_invoice", goal="delete")
    with pytest.raises(PolicyDenied):
        kernel.grant_capability(req, reader_principal, justification="nope")

    denied = kernel.query_traces(TraceQuery(event_type="deny"))
    assert len(denied) == 1
    assert denied[0].capability_id == "billing.delete_invoice"
    # Filtering by a principal who did nothing yields nothing.
    assert kernel.query_traces(TraceQuery(principal_id="ghost")) == []
