"""Named executable suite for Weaver invariants I-01, I-02 and I-06 (#199).

These tests intentionally use the public Kernel/token/firewall-facing APIs where
possible. Their job is architectural: a refactor that breaks a documented Weaver
invariant should fail a file named ``test_invariants.py`` loudly, even when more
specialized tests elsewhere still pass.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    DriverError,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
    TokenInvalid,
    TokenScopeError,
    TraceStore,
)

_CAPABILITY_ID = "records.read"
_SECRET = "named-invariant-suite-secret"
_SENTINEL = "Bearer INVARIANT-SENTINEL-DO-NOT-LEAK"


def _build_kernel(
    result_factory: Callable[[], Any],
    *,
    constraints: dict[str, Any] | None = None,
) -> tuple[
    Kernel,
    HMACTokenProvider,
    TraceStore,
    Principal,
    Any,
    list[str],
]:
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id=_CAPABILITY_ID,
            name="Read records",
            description="Invariant-suite fixture",
            safety_class=SafetyClass.READ,
        )
    )

    calls: list[str] = []
    driver = InMemoryDriver(driver_id="fixture")

    def handler(_ctx: object) -> Any:
        calls.append(_CAPABILITY_ID)
        return result_factory()

    driver.register_handler(_CAPABILITY_ID, handler)
    provider = HMACTokenProvider(secret=_SECRET)
    traces = TraceStore()
    kernel = Kernel(
        registry=registry,
        token_provider=provider,
        router=StaticRouter(routes={_CAPABILITY_ID: ["fixture"]}),
        trace_store=traces,
    )
    kernel.register_driver(driver)
    principal = Principal(principal_id="alice", roles=["reader"])
    token = provider.issue(
        _CAPABILITY_ID,
        principal.principal_id,
        constraints=constraints,
    )
    return kernel, provider, traces, principal, token, calls


# I-01 — every tool result crosses the context boundary before LLM-safe output.


@pytest.mark.asyncio
async def test_i01_non_admin_raw_request_is_bounded_and_redacted() -> None:
    """I-01: a non-admin cannot turn a raw request into raw driver output."""
    kernel, _provider, _traces, principal, token, _calls = _build_kernel(
        lambda: [{"id": 1, "authorization": _SENTINEL}]
    )

    frame = await kernel.invoke(token, principal=principal, args={}, response_mode="raw")

    assert frame.response_mode == "summary"
    assert frame.raw_data is None
    assert _SENTINEL not in repr(frame)


@pytest.mark.asyncio
async def test_i01_allowed_fields_cannot_be_widened_by_driver_output() -> None:
    """I-01: signed field constraints bound the LLM-safe table projection."""
    kernel, _provider, _traces, principal, token, _calls = _build_kernel(
        lambda: [{"id": 1, "internal": "must-not-cross-boundary"}],
        constraints={"allowed_fields": ["id"]},
    )

    frame = await kernel.invoke(token, principal=principal, args={}, response_mode="table")

    assert frame.table_preview == [{"id": 1}]
    assert "must-not-cross-boundary" not in repr(frame)


@pytest.mark.asyncio
async def test_i01_handle_only_exposes_reference_not_driver_payload() -> None:
    """I-01: handle-only mode returns a reference without inline result data."""
    kernel, _provider, _traces, principal, token, _calls = _build_kernel(
        lambda: [{"id": 1, "secret": _SENTINEL}]
    )

    frame = await kernel.invoke(
        token,
        principal=principal,
        args={},
        response_mode="handle_only",
    )

    assert frame.handle is not None
    assert frame.table_preview == []
    assert frame.facts == []
    assert frame.raw_data is None
    assert _SENTINEL not in repr(frame)


# I-02 — no execution without verified authority; executions are auditable.


@pytest.mark.asyncio
async def test_i02_invalid_token_never_reaches_driver() -> None:
    """I-02: verification failure occurs before the driver is called."""
    kernel, _provider, _traces, principal, token, calls = _build_kernel(lambda: [{"ok": True}])
    token.signature = "0" * len(token.signature)

    with pytest.raises(TokenInvalid):
        await kernel.invoke(token, principal=principal, args={})

    assert calls == []


@pytest.mark.asyncio
async def test_i02_successful_execution_has_explainable_trace() -> None:
    """I-02: a successful mediated execution leaves one explainable receipt."""
    kernel, _provider, traces, principal, token, calls = _build_kernel(
        lambda: [{"id": 1, "status": "ok"}]
    )

    frame = await kernel.invoke(token, principal=principal, args={})
    trace = kernel.explain(frame.action_id)

    assert calls == [_CAPABILITY_ID]
    assert trace.capability_id == _CAPABILITY_ID
    assert trace.principal_id == principal.principal_id
    assert trace.error is None
    assert len(traces.list_all()) == 1


@pytest.mark.asyncio
async def test_i02_driver_failure_is_still_audited() -> None:
    """I-02: once execution starts, driver failure cannot escape untraced."""

    def fail() -> Any:
        raise RuntimeError("synthetic driver failure")

    kernel, _provider, traces, principal, token, calls = _build_kernel(fail)

    with pytest.raises(DriverError):
        await kernel.invoke(token, principal=principal, args={})

    assert calls == [_CAPABILITY_ID]
    recorded = traces.list_all()
    assert len(recorded) == 1
    assert recorded[0].capability_id == _CAPABILITY_ID
    assert recorded[0].principal_id == principal.principal_id
    assert recorded[0].error is not None
    assert "synthetic driver failure" in recorded[0].error


# I-06 — signed grants bind principal + capability + constraints.


def test_i06_token_cannot_cross_principal_boundary() -> None:
    """I-06: a token minted for Alice cannot authorize Bob."""
    provider = HMACTokenProvider(secret=_SECRET)
    token = provider.issue(_CAPABILITY_ID, "alice")

    with pytest.raises(TokenScopeError):
        provider.verify(
            token,
            expected_principal_id="bob",
            expected_capability_id=_CAPABILITY_ID,
        )


def test_i06_token_cannot_cross_capability_boundary() -> None:
    """I-06: a grant for one capability cannot authorize another."""
    provider = HMACTokenProvider(secret=_SECRET)
    token = provider.issue(_CAPABILITY_ID, "alice")

    with pytest.raises(TokenScopeError):
        provider.verify(
            token,
            expected_principal_id="alice",
            expected_capability_id="records.delete",
        )


def test_i06_mutating_signed_constraints_invalidates_token() -> None:
    """I-06: constraints are inside the signed payload and cannot be widened."""
    provider = HMACTokenProvider(secret=_SECRET)
    token = provider.issue(
        _CAPABILITY_ID,
        "alice",
        constraints={"allowed_fields": ["id"]},
    )
    token.constraints["allowed_fields"] = ["id", "secret"]

    with pytest.raises(TokenInvalid):
        provider.verify(
            token,
            expected_principal_id="alice",
            expected_capability_id=_CAPABILITY_ID,
        )
