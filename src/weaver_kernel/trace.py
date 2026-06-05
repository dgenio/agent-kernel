"""TraceStore: in-memory audit trail for kernel invocations.

This module also defines the **stable export contract** for
:class:`~weaver_kernel.models.ActionTrace` records
(:func:`export_action_trace` / :func:`export_action_traces`) so downstream
analysis tools — for example a LessonWeaver-style lesson-extraction layer —
can consume traces without depending on agent-kernel internals.

The export is intentionally distinct from the OpenTelemetry observability
export in :mod:`weaver_kernel.otel`: OTel emits live spans and metrics for
monitoring, whereas this contract produces a stable, JSON-serialisable audit
record per invocation for offline analysis. See ``docs/trace_export.md``.

Privacy: the export is derived **only** from already-redaction-safe
:class:`ActionTrace` fields. ``args`` has memory payloads stripped at record
time and ``result_summary`` carries counts/flags only — never raw driver data
— so exporting cannot widen the I-01 firewall boundary or leak sensitive
payloads. The contract adds no field that the trace did not already hold.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .errors import AgentKernelError
from .models import ActionTrace

# ── Export contract ─────────────────────────────────────────────────────────

TRACE_EXPORT_SCHEMA = "weaver_kernel.action_trace_export"
"""Stable schema identifier embedded in every exported envelope."""

TRACE_EXPORT_VERSION = "1"
"""Schema version of the export envelope. Bumped only on a breaking change to
the field shape; new optional fields may be added without a bump."""


def export_action_trace(
    trace: ActionTrace,
    *,
    correction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialise a single :class:`ActionTrace` to the stable export shape.

    The returned dict is JSON-serialisable as long as ``trace.args`` and
    ``trace.result_summary`` hold JSON-compatible values (they do for traces
    the kernel records). No raw driver output is added: every field is copied
    verbatim from the already-redaction-safe trace.

    Args:
        trace: The recorded action trace to export.
        correction: Optional human-correction metadata to attach (e.g.
            ``{"corrected_by": "reviewer", "note": "..."}``). agent-kernel does
            not record corrections itself; a downstream tool supplies them at
            export time. ``None`` when no correction is available.

    Returns:
        A dict with the stable export fields. ``status`` is ``"failed"`` when
        the invocation recorded an ``error`` and ``"succeeded"`` otherwise.
        (A *denied* request never produces an :class:`ActionTrace` — policy
        gates before invocation, per I-02 — so the export only ever describes
        authorised invocations; denials surface via
        :class:`~weaver_kernel.PolicyDenied` / ``explain_denial``.)
    """
    return {
        "action_id": trace.action_id,
        "capability_id": trace.capability_id,
        "principal_id": trace.principal_id,
        "token_id": trace.token_id,
        "invoked_at": trace.invoked_at.isoformat(),
        "response_mode": trace.response_mode,
        "driver_id": trace.driver_id,
        "handle_id": trace.handle_id,
        "sensitivity": trace.sensitivity.value,
        "status": "failed" if trace.error is not None else "succeeded",
        "error": trace.error,
        "args": trace.args,
        "result_summary": trace.result_summary,
        "correction": correction,
    }


def export_action_traces(
    traces: Iterable[ActionTrace],
    *,
    corrections: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Export an iterable of traces as a versioned, JSON-serialisable envelope.

    Args:
        traces: The action traces to export (e.g. ``TraceStore.list_all()``).
        corrections: Optional mapping of ``action_id`` → human-correction
            metadata, applied per trace. Entries with no matching trace are
            ignored; traces with no entry get ``correction=None``.

    Returns:
        A dict ``{"schema", "version", "traces": [...]}`` where each entry is
        the result of :func:`export_action_trace`.
    """
    corrections = corrections or {}
    return {
        "schema": TRACE_EXPORT_SCHEMA,
        "version": TRACE_EXPORT_VERSION,
        "traces": [
            export_action_trace(trace, correction=corrections.get(trace.action_id))
            for trace in traces
        ],
    }


class TraceStore:
    """Stores :class:`ActionTrace` records indexed by ``action_id``.

    All invocations recorded by the :class:`~weaver_kernel.kernel.Kernel` are
    retrievable here for audit and explainability purposes.
    """

    def __init__(self) -> None:
        self._traces: dict[str, ActionTrace] = {}

    def record(self, trace: ActionTrace) -> None:
        """Store an action trace.

        Args:
            trace: The :class:`ActionTrace` to record.
        """
        self._traces[trace.action_id] = trace

    def get(self, action_id: str) -> ActionTrace:
        """Retrieve an action trace by its ID.

        Args:
            action_id: The unique action identifier.

        Returns:
            The :class:`ActionTrace` for that action.

        Raises:
            AgentKernelError: If no trace with that ID exists.
        """
        try:
            return self._traces[action_id]
        except KeyError:
            raise AgentKernelError(f"No action trace found for action_id='{action_id}'.") from None

    def list_all(self) -> list[ActionTrace]:
        """Return all recorded traces in insertion order."""
        return list(self._traces.values())
