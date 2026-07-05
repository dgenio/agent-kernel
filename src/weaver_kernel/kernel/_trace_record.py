"""Audit-trace builders for the invoke pipeline.

Split out of :mod:`._invoke` to keep it within its ratchet ceiling
(AGENTS.md). These helpers are shared with :mod:`._stream` (streaming
invocations) and :mod:`._audit` (denial/expansion events) so every audit
record in the kernel redacts sensitive data through the same path.
"""

from __future__ import annotations

import datetime
from typing import Any, cast

from ..enums import SensitivityTag
from ..firewall.redaction import redact
from ..models import ActionTrace, Frame, ResponseMode, TraceEventType
from ..stores import TraceStoreProtocol

_MEMORY_CAPABILITY_PREFIX = "memory."
_MEMORY_SENSITIVE_ARG_KEYS: frozenset[str] = frozenset(
    {"payload", "content", "value", "memory", "text", "body"}
)


def _redact_args_for_trace(capability_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive values from :class:`ActionTrace.args` before storage.

    The trace store is the long-lived audit record; if invocation arguments
    carry user content, secrets passed as parameters, or PII, storing them raw
    makes the store itself a sensitive-data sink — undermining the I-01
    boundary the :class:`Firewall` enforces on *outputs*. Two layers apply:

    1. **Memory payload stripping.** Memory capabilities (``capability_id``
       starting with ``"memory."``) carry durable free text under known keys
       (``payload``, ``content``, …); those values are replaced wholesale with
       ``"[REDACTED]"`` (keys preserved so audit can confirm a payload was
       provided).
    2. **General pattern/field redaction for every capability.** All args are
       then passed through the same :func:`~weaver_kernel.firewall.redaction.redact`
       used on driver output, so inline secrets/PII and sensitive field names
       are scrubbed regardless of the capability namespace (#172).
    """
    if capability_id.startswith(_MEMORY_CAPABILITY_PREFIX):
        args = {
            k: ("[REDACTED]" if k.lower() in _MEMORY_SENSITIVE_ARG_KEYS else v)
            for k, v in args.items()
        }
    redacted, _ = redact(args)
    return cast(dict[str, Any], redacted)


def _redact_trace_text(text: str) -> str:
    """Scrub inline secrets/PII from free text before it enters a trace.

    ``DriverError`` messages can embed raw response bodies (e.g. up to 200
    characters of an HTTP error body), so error text recorded on an
    :class:`ActionTrace` is run through the firewall's string redactor first.
    """
    redacted, _ = redact(text)
    return cast(str, redacted)


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


def record_failure_trace(
    *,
    action_id: str,
    capability_id: str,
    principal_id: str,
    token_id: str,
    args: dict[str, Any],
    response_mode: ResponseMode,
    error_message: str,
    trace_store: TraceStoreProtocol,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
    driver_id: str = "",
    reason_code: str | None = None,
    event_type: TraceEventType = "invoke",
) -> None:
    """Persist an :class:`ActionTrace` for a failed run.

    Args:
        driver_id: The driver implicated in the failure — the one that ran and
            then failed downstream, or the last one attempted when every driver
            failed. Empty when no driver was reached (e.g. a pre-execution
            constraint or rate-limit denial).
        reason_code: Stable machine-readable code for the failure, when one
            applies (e.g. an invoke-time policy denial). ``None`` for
            unclassified driver failures.
        event_type: ``"invoke"`` for a driver-execution failure (default);
            ``"deny"`` for an invoke-time policy refusal (argument-constraint
            violation, per-invocation rate limit) that never reached a driver.
    """
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
            error=_redact_trace_text(error_message),
            reason_code=reason_code,
            event_type=event_type,
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
    trace_store: TraceStoreProtocol,
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


__all__ = [
    "record_failure_trace",
    "record_success_trace",
]
