"""Audit-record builders for non-invoke events (#175).

Auditability extends beyond successful invocations to other authorized
data-access events and grant-time authorization decisions, which were previously
only logged. These helpers record two of them as first-class
:class:`~weaver_kernel.models.ActionTrace` entries: a successful handle
*expansion* (``event_type="expand"``, a data-access event) and a grant-time
policy *denial* (``event_type="deny"``, raised by
:meth:`PolicyEngine.evaluate`). So :meth:`Kernel.explain`, the trace query API,
and the audit CLI can answer "who was refused a grant, when, and why" and "which
rows were expanded".

Scope note: only grant-time denials are recorded here. Expansion-time access
failures (principal/constraint violations raised by ``HandleStore.expand``)
still surface as exceptions and logs, not ``"deny"`` traces.

The redaction helpers are shared with :mod:`._invoke` so an expansion's query
arguments and a denial's message pass through the same firewall scrub used for
invocation traces — the audit store never becomes a sensitive-data sink.
"""

from __future__ import annotations

import datetime
import uuid

from ..models import ActionTrace, Frame
from ..stores import TraceStoreProtocol
from ._invoke import _frame_result_summary, _redact_args_for_trace, _redact_trace_text


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def record_denial_trace(
    *,
    capability_id: str,
    principal_id: str,
    reason_code: str | None,
    message: str,
    trace_store: TraceStoreProtocol,
) -> None:
    """Record a ``"deny"`` audit event for a refused grant.

    No token is issued on a denial, so ``token_id`` and ``driver_id`` are empty;
    the stable ``reason_code`` and the (redacted) denial ``message`` capture why.
    """
    trace_store.record(
        ActionTrace(
            action_id=str(uuid.uuid4()),
            capability_id=capability_id,
            principal_id=principal_id,
            token_id="",
            invoked_at=_now(),
            args={},
            response_mode="summary",
            driver_id="",
            event_type="deny",
            reason_code=reason_code,
            error=_redact_trace_text(message),
        )
    )


def record_expansion_trace(
    *,
    action_id: str,
    capability_id: str,
    principal_id: str,
    handle_id: str,
    query: dict[str, object],
    frame: Frame,
    trace_store: TraceStoreProtocol,
) -> None:
    """Record an ``"expand"`` audit event for a served handle expansion.

    Args mirror the expansion query (redacted like invocation args) and the
    redaction-safe result summary is taken from the already-firewalled
    expansion :class:`Frame`, so no raw row data enters the trail.
    """
    trace_store.record(
        ActionTrace(
            action_id=action_id,
            capability_id=capability_id,
            principal_id=principal_id,
            token_id="",
            invoked_at=_now(),
            args=_redact_args_for_trace(capability_id, dict(query)),
            response_mode=frame.response_mode,
            driver_id="",
            handle_id=handle_id,
            event_type="expand",
            result_summary=_frame_result_summary(frame),
        )
    )


__all__ = ["record_denial_trace", "record_expansion_trace"]
