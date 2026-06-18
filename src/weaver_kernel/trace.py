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

import logging
from collections.abc import Iterable
from typing import Any

from .errors import AgentKernelError
from .models import ActionTrace
from .trace_query import TraceQuery, query_traces

logger = logging.getLogger("weaver_kernel.trace")

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
        the trace recorded an ``error`` and ``"succeeded"`` otherwise.
        ``event_type`` distinguishes ``"invoke"`` (a capability invocation),
        ``"expand"`` (a handle-expansion data-access event), and ``"deny"`` (a
        policy denial at grant time, carrying a stable ``reason_code``); see
        #175. A denial therefore *does* appear in the export as a ``"deny"``
        event with ``status == "failed"`` — its structured form is still
        available via :class:`~weaver_kernel.PolicyDenied` / ``explain_denial``.
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
        "event_type": trace.event_type,
        "reason_code": trace.reason_code,
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


_DEFAULT_MAX_ENTRIES = 10_000


class TraceStore:
    """Stores :class:`ActionTrace` records indexed by ``action_id``.

    All invocations recorded by the :class:`~weaver_kernel.kernel.Kernel` are
    retrievable here for audit and explainability purposes.

    Memory is bounded (#182): a long-lived agent process records one trace per
    invocation, so the store caps itself at ``max_entries`` and evicts the
    oldest record (insertion order, FIFO) when the cap is exceeded. Eviction
    discards audit data, so it is *loud* — the first eviction logs a warning and
    :attr:`evicted_count` records how many records were dropped. Deployments
    that need unbounded retention should use a durable backend
    (:class:`~weaver_kernel.stores.SQLiteTraceStore` /
    :class:`~weaver_kernel.stores.JsonlTraceStore`).
    """

    def __init__(self, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        """Initialise the store.

        Args:
            max_entries: Maximum number of records retained. Must be positive;
                defaults high enough (10 000) that typical sessions never evict.

        Raises:
            AgentKernelError: If ``max_entries`` is not positive.
        """
        if max_entries <= 0:
            raise AgentKernelError(f"TraceStore max_entries must be positive, got {max_entries}.")
        self._traces: dict[str, ActionTrace] = {}
        self._max_entries = max_entries
        self.evicted_count = 0
        self._eviction_warned = False

    def record(self, trace: ActionTrace) -> None:
        """Store an action trace, evicting the oldest if the cap is exceeded.

        Re-recording an existing ``action_id`` overwrites in place and never
        evicts (the record count is unchanged). A genuinely new record beyond
        :attr:`max_entries` drops the oldest record first.

        Args:
            trace: The :class:`ActionTrace` to record.
        """
        self._traces[trace.action_id] = trace
        while len(self._traces) > self._max_entries:
            oldest_id = next(iter(self._traces))
            del self._traces[oldest_id]
            self.evicted_count += 1
            if not self._eviction_warned:
                logger.warning(
                    "trace_store_eviction",
                    extra={"max_entries": self._max_entries, "evicted_action_id": oldest_id},
                )
                self._eviction_warned = True

    def query(self, query: TraceQuery) -> list[ActionTrace]:
        """Return recorded traces matching *query*, ordered and paginated.

        See :func:`~weaver_kernel.trace_query.query_traces` for ordering and
        pagination semantics.
        """
        return query_traces(self._traces.values(), query)

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
