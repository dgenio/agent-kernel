"""Internal helpers for :meth:`Kernel.invoke` execution.

Split out of :mod:`kernel` to keep the public API module ≤ 300 lines
(AGENTS.md). Each helper preserves the invariants documented in
``docs/agent-context/invariants.md``:

* Firewall is *mandatory* — :class:`RawResult` never leaves
  :func:`perform_invoke` without being transformed by
  :func:`Firewall.transform`.
* Admin gate for ``raw`` is mirrored in :func:`resolve_effective_mode`.
* Failed runs still produce an :class:`ActionTrace` (via
  :func:`record_failure_trace`) so I-02 (auditability) holds even on
  driver failure.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..drivers.base import ExecutionContext
from ..enums import SafetyClass
from ..errors import DriverError, RateLimitExceeded, TokenScopeError
from ..firewall.budget_manager import BudgetManager
from ..models import (
    Capability,
    Frame,
    Handle,
    Principal,
    ResponseMode,
    RoutePlan,
)
from ..policy_reasons import DenialReason
from ..tokens import CapabilityToken
from ._arg_constraints import validate_arg_constraints
from ._driver_exec import execute_with_fallback, resolve_invoke_timeout
from ._trace_record import _frame_result_summary, record_failure_trace, record_success_trace

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")


def resolve_effective_mode(
    *,
    response_mode: ResponseMode,
    principal: Principal,
    budget_manager: BudgetManager | None,
) -> ResponseMode:
    """Apply the admin gate and (optionally) budget escalation.

    The Firewall downgrades ``raw`` to ``summary`` for non-admin
    principals; this helper performs the same downgrade *before* handle
    creation so a non-admin asking for raw still gets a usable handle
    in the summary frame.

    When a :class:`BudgetManager` is attached, the resulting mode is
    further escalated via :meth:`BudgetManager.suggested_mode`.
    """
    effective: ResponseMode = response_mode
    if response_mode == "raw" and "admin" not in principal.roles:
        effective = "summary"
    if budget_manager is not None:
        effective = budget_manager.suggested_mode(effective)
    return effective


def _check_invoke_rate_limit(
    kernel: Kernel, *, principal_id: str, capability_id: str, safety_class: SafetyClass
) -> None:
    """Enforce the opt-in per-invocation rate limit, if configured (#170).

    A no-op unless the kernel was constructed with ``invoke_rate_limits``.
    Checks and records against the same limiter *synchronously* (no
    ``await`` in between) so two concurrent ``invoke()`` calls on the same
    principal+capability cannot both pass the check before either records —
    see the concurrency caveat in ``docs/security.md``.

    Raises:
        RateLimitExceeded: If the sliding-window limit for *safety_class*
            would be exceeded by this invocation.
    """
    limits = kernel._invoke_limits
    if limits is None:
        return
    limit_window = limits.get(safety_class)
    if limit_window is None:
        return
    limit, window_seconds = limit_window
    key = f"{principal_id}:{capability_id}"
    limiter = kernel._invoke_limiter
    if not limiter.check(key, limit, window_seconds):
        raise RateLimitExceeded(
            f"Per-invocation rate limit exceeded for '{principal_id}' on "
            f"'{capability_id}' ({limit} per {window_seconds}s).",
            reason_code=str(DenialReason.INVOKE_RATE_LIMITED),
        )
    limiter.record(key)


def _enforce_pre_execution(
    kernel: Kernel,
    *,
    token: CapabilityToken,
    args: dict[str, Any],
    principal: Principal,
    capability: Capability,
    action_id: str,
    effective_mode: ResponseMode,
    response_mode: ResponseMode,
) -> None:
    """Run checks that must pass *before* a driver runs or budget is reserved.

    Argument constraints (#183) and, if configured, the per-invocation rate
    limit (#170). A violation records a ``"deny"`` failure trace (I-02) and
    re-raises — never a bare exception escaping unaudited.

    Raises:
        TokenScopeError: If *args* violates the token's ``constraints["args"]``.
        RateLimitExceeded: If invoke-time rate limiting is enabled and the
            window limit for this principal+capability is exceeded.
    """
    try:
        validate_arg_constraints(token.constraints, args)
        _check_invoke_rate_limit(
            kernel,
            principal_id=principal.principal_id,
            capability_id=token.capability_id,
            safety_class=capability.safety_class,
        )
    except (TokenScopeError, RateLimitExceeded) as exc:
        record_failure_trace(
            action_id=action_id,
            capability_id=token.capability_id,
            principal_id=principal.principal_id,
            token_id=token.token_id,
            args=args,
            response_mode=effective_mode,
            error_message=str(exc),
            trace_store=kernel._traces,
            sensitivity=capability.sensitivity,
            reason_code=exc.reason_code,
            event_type="deny",
        )
        kernel._stats.on_invocation(
            failed=True, fallback=False, redacted=False, downgraded=effective_mode != response_mode
        )
        raise


async def perform_invoke(
    kernel: Kernel,
    *,
    token: CapabilityToken,
    principal: Principal,
    args: dict[str, Any],
    response_mode: ResponseMode,
    plan: RoutePlan,
    capability: Capability,
) -> Frame:
    """Run the non-dry-run invocation pipeline end-to-end.

    Called by :meth:`Kernel.invoke` after token verification and
    capability lookup. Performs admin-gate, budget allocation, driver
    fallback, handle creation, firewall transform, budget
    reconciliation, and audit trace recording.

    Args:
        kernel: The orchestrating :class:`Kernel` (private accessors used
            for the driver map, firewall, handle store, and trace store).
        token: The verified token authorising this invocation.
        principal: The invoking principal.
        args: Driver arguments.
        response_mode: The caller-requested response mode.
        plan: The router-resolved :class:`RoutePlan` for *token*.
        capability: The resolved :class:`Capability`; its
            :attr:`~weaver_kernel.models.Capability.sensitivity` is copied onto
            the recorded :class:`ActionTrace`.
    """
    action_id = str(uuid.uuid4())
    # Resolve the optional per-invocation deadline (#191) before reserving
    # budget so an invalid signed constraint fails fast without leaking a
    # reservation.
    invoke_timeout = resolve_invoke_timeout(token.constraints)
    effective_mode = resolve_effective_mode(
        response_mode=response_mode,
        principal=principal,
        budget_manager=kernel.budget,
    )
    # #170, #183: argument constraints and (if configured) the per-invocation
    # rate limit are enforced before budget reservation, so a violation never
    # leaks a reservation and never reaches a driver.
    _enforce_pre_execution(
        kernel,
        token=token,
        args=args,
        principal=principal,
        capability=capability,
        action_id=action_id,
        effective_mode=effective_mode,
        response_mode=response_mode,
    )
    reserved_tokens: int | None = None
    if kernel.budget is not None:
        reserved_tokens = await kernel.budget.allocate()

    log_ctx = {
        "action_id": action_id,
        "principal_id": principal.principal_id,
        "capability_id": token.capability_id,
    }
    logger.info(
        "invoke_start",
        extra={
            **log_ctx,
            "token_id": token.token_id,
            "response_mode": response_mode,
            "effective_mode": effective_mode,
        },
    )

    ctx = ExecutionContext(
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        args=args,
        constraints=token.constraints,
        action_id=action_id,
    )
    downgraded = effective_mode != response_mode
    used_driver_id = ""
    fell_back = False

    def _record_invoke_failure(message: str, driver_id: str) -> None:
        """Log + audit a failed invocation, recording the effective mode (#152)."""
        logger.warning("invoke_failure", extra={**log_ctx, "error": message})
        record_failure_trace(
            action_id=action_id,
            capability_id=token.capability_id,
            principal_id=principal.principal_id,
            token_id=token.token_id,
            args=args,
            response_mode=effective_mode,
            error_message=message,
            trace_store=kernel._traces,
            sensitivity=capability.sensitivity,
            driver_id=driver_id,
        )
        kernel._stats.on_invocation(
            failed=True, fallback=fell_back, redacted=False, downgraded=downgraded
        )

    # I-02: every exit past the budget reservation — a driver failure, a fault
    # in the post-driver pipeline (handle creation, firewall transform, token
    # counting), or task cancellation — must release the reservation exactly
    # once and leave an audit trace. The reservation is freed in a single
    # ``finally`` (which also covers ``CancelledError``, not an ``Exception``);
    # each path records its own failure trace before propagating (#152, #191).
    handle: Handle | None = None
    reservation_settled = False
    try:
        raw_result, used_driver_id, last_error, fell_back = await execute_with_fallback(
            kernel._driver_map, plan, ctx=ctx, log_ctx=log_ctx, timeout=invoke_timeout
        )
        if raw_result is None:
            err_msg = str(last_error) if last_error else "No drivers available."
            _record_invoke_failure(err_msg, used_driver_id)
            raise DriverError(
                f"All drivers failed for capability '{token.capability_id}'. Last error: {err_msg}"
            )
        if effective_mode != "raw":
            handle = kernel._handles.store(
                capability_id=token.capability_id,
                data=raw_result.data,
                principal_id=principal.principal_id,
                constraints=token.constraints,
            )
            kernel._stats.on_handle_store()
        frame = kernel._fw.transform(
            raw_result,
            action_id=action_id,
            principal_id=principal.principal_id,
            principal_roles=list(principal.roles),
            response_mode=effective_mode,
            constraints=token.constraints,
            handle=handle,
        )
        if kernel.budget is not None and reserved_tokens is not None:
            actual_tokens = kernel.budget.count_tokens(_frame_payload(frame))
            await kernel.budget.record_usage(actual_tokens, reserved=reserved_tokens)
        reservation_settled = True  # consumed via record_usage (or no budget configured)
    except DriverError:
        raise  # already audited by _record_invoke_failure above
    except asyncio.CancelledError:
        _record_invoke_failure("invocation cancelled", used_driver_id)
        raise
    except Exception as exc:
        _record_invoke_failure(str(exc), used_driver_id)
        raise
    finally:
        if not reservation_settled and kernel.budget is not None and reserved_tokens is not None:
            await kernel.budget.release(reserved_tokens)

    record_success_trace(
        action_id=action_id,
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        token_id=token.token_id,
        args=args,
        response_mode=frame.response_mode,
        driver_id=used_driver_id,
        handle_id=handle.handle_id if handle else None,
        result_summary=_frame_result_summary(frame),
        trace_store=kernel._traces,
        sensitivity=capability.sensitivity,
    )
    kernel._stats.on_invocation(
        failed=False,
        fallback=fell_back,
        redacted=bool(frame.warnings),
        downgraded=frame.response_mode != response_mode,
    )
    logger.info(
        "invoke_success",
        extra={
            **log_ctx,
            "response_mode": frame.response_mode,
            "driver_id": used_driver_id,
        },
    )
    # A single-shot invoke always returns a final Frame. Streaming callers
    # control ``is_final`` themselves in ``_stream.py``.
    return replace(frame, is_final=True)


def _frame_payload(frame: Frame) -> Any:
    """Return the LLM-facing payload from a :class:`Frame` for token counting."""
    if frame.response_mode == "raw":
        return frame.raw_data
    if frame.response_mode == "table":
        return frame.table_preview
    if frame.response_mode == "handle_only":
        return None
    return frame.facts


__all__ = [
    "perform_invoke",
    "resolve_effective_mode",
    "record_failure_trace",
    "record_success_trace",
]
