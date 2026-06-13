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

import datetime
import logging
import uuid
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..drivers.base import Driver, ExecutionContext
from ..enums import SensitivityTag
from ..errors import DriverError
from ..firewall.budget_manager import BudgetManager
from ..models import (
    ActionTrace,
    Capability,
    Frame,
    Handle,
    Principal,
    RawResult,
    ResponseMode,
    RoutePlan,
)
from ..tokens import CapabilityToken
from ..trace import TraceStore

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")

_MEMORY_CAPABILITY_PREFIX = "memory."
_MEMORY_SENSITIVE_ARG_KEYS: frozenset[str] = frozenset(
    {"payload", "content", "value", "memory", "text", "body"}
)


def _redact_args_for_trace(capability_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Strip raw memory payloads from :class:`ActionTrace.args`.

    Memory capabilities (``capability_id`` starting with ``"memory."``) may
    carry durable text the principal is committing to or fetching from
    long-term memory. Tracing the raw payload would defeat the I-01 boundary
    the :class:`Firewall` enforces for outputs — so we apply an equivalent
    input-side redaction at trace-record time. Keys are preserved (so audit
    can confirm a payload was provided); sensitive values become
    ``"[REDACTED]"``. Non-memory capabilities are returned unchanged.
    """
    if not capability_id.startswith(_MEMORY_CAPABILITY_PREFIX):
        return args
    return {
        k: ("[REDACTED]" if k.lower() in _MEMORY_SENSITIVE_ARG_KEYS else v)
        for k, v in args.items()
    }


def _frame_result_summary(frame: Frame) -> dict[str, Any]:
    """Build a redaction-safe result summary from a *firewalled* Frame.

    Records only counts and flags taken from the already-transformed Frame —
    never raw driver data — so it preserves the I-01 boundary the Firewall
    enforces and keeps sensitive payloads out of the audit trail. Stored on
    :attr:`~weaver_kernel.models.ActionTrace.result_summary` so an invocation's
    outcome (e.g. a safety check's pass/block decision) is auditable via
    :meth:`~weaver_kernel.Kernel.explain`.
    """
    return {
        "fact_count": len(frame.facts),
        "row_count": len(frame.table_preview),
        "warning_count": len(frame.warnings),
        "has_handle": frame.handle is not None,
    }


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


async def execute_with_fallback(
    drivers: dict[str, Driver],
    plan: RoutePlan,
    *,
    ctx: ExecutionContext,
    log_ctx: dict[str, str],
) -> tuple[RawResult | None, str, Exception | None]:
    """Iterate the route plan's drivers until one succeeds.

    Returns:
        ``(raw_result, driver_id, last_error)``. ``raw_result`` is
        ``None`` if every driver failed.
    """
    last_error: Exception | None = None
    for driver_id in plan.driver_ids:
        driver = drivers.get(driver_id)
        if driver is None:
            continue
        try:
            raw_result = await driver.execute(ctx)
            logger.debug("driver_success", extra={**log_ctx, "driver_id": driver_id})
            return raw_result, driver_id, None
        except DriverError as exc:
            logger.warning(
                "driver_failure",
                extra={**log_ctx, "driver_id": driver_id, "error": str(exc)},
            )
            last_error = exc
            continue
    return None, "", last_error


def record_failure_trace(
    *,
    action_id: str,
    capability_id: str,
    principal_id: str,
    token_id: str,
    args: dict[str, Any],
    response_mode: ResponseMode,
    error_message: str,
    trace_store: TraceStore,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
) -> None:
    """Persist an :class:`ActionTrace` for a run where no driver succeeded."""
    trace_store.record(
        ActionTrace(
            action_id=action_id,
            capability_id=capability_id,
            principal_id=principal_id,
            token_id=token_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            args=_redact_args_for_trace(capability_id, args),
            response_mode=response_mode,
            driver_id="",
            sensitivity=sensitivity,
            error=error_message,
        )
    )


def record_success_trace(
    *,
    action_id: str,
    capability_id: str,
    principal_id: str,
    token_id: str,
    args: dict[str, Any],
    response_mode: ResponseMode,
    driver_id: str,
    handle_id: str | None,
    result_summary: dict[str, Any] | None,
    trace_store: TraceStore,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
) -> None:
    """Persist an :class:`ActionTrace` for a successful invocation."""
    trace_store.record(
        ActionTrace(
            action_id=action_id,
            capability_id=capability_id,
            principal_id=principal_id,
            token_id=token_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            args=_redact_args_for_trace(capability_id, args),
            response_mode=response_mode,
            driver_id=driver_id,
            sensitivity=sensitivity,
            handle_id=handle_id,
            result_summary=result_summary,
        )
    )


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
    effective_mode = resolve_effective_mode(
        response_mode=response_mode,
        principal=principal,
        budget_manager=kernel.budget,
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
    raw_result, used_driver_id, last_error = await execute_with_fallback(
        kernel._driver_map, plan, ctx=ctx, log_ctx=log_ctx
    )

    if raw_result is None:
        if kernel.budget is not None and reserved_tokens is not None:
            await kernel.budget.release(reserved_tokens)
        err_msg = str(last_error) if last_error else "No drivers available."
        logger.warning("invoke_failure", extra={**log_ctx, "error": err_msg})
        record_failure_trace(
            action_id=action_id,
            capability_id=token.capability_id,
            principal_id=principal.principal_id,
            token_id=token.token_id,
            args=args,
            response_mode=response_mode,
            error_message=err_msg,
            trace_store=kernel._traces,
            sensitivity=capability.sensitivity,
        )
        raise DriverError(
            f"All drivers failed for capability '{token.capability_id}'. Last error: {err_msg}"
        )

    handle: Handle | None = None
    if effective_mode != "raw":
        handle = kernel._handles.store(
            capability_id=token.capability_id,
            data=raw_result.data,
            principal_id=principal.principal_id,
            constraints=token.constraints,
        )

    reservation_consumed = False
    try:
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
        reservation_consumed = True
    finally:
        if not reservation_consumed and kernel.budget is not None and reserved_tokens is not None:
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
    "execute_with_fallback",
    "record_failure_trace",
    "record_success_trace",
]
