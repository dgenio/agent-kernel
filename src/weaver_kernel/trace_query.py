"""Filtering and pagination over :class:`~weaver_kernel.models.ActionTrace` records.

The audit trail is the product's flagship artifact, yet per-``action_id`` lookup
is the only access today. :class:`TraceQuery` plus the pure
:func:`query_traces` give operators a small, stable filter surface ("what did
principal X do in the last hour?", "which capabilities failed today?") that
every :class:`~weaver_kernel.stores.TraceStoreProtocol` backend shares (#177).

The function is pure and deterministic: identical inputs yield identical output,
ordered by ``(invoked_at, action_id)`` so pagination slices are disjoint and
complete (AGENTS.md forbids non-deterministic ordering).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from .errors import AgentKernelError
from .models import ActionTrace, TraceEventType

Outcome = Literal["succeeded", "failed"]
"""Coarse invocation outcome: ``"succeeded"`` when no ``error`` was recorded,
``"failed"`` otherwise (a denial records its reason as an ``error``)."""


@dataclass(slots=True)
class TraceQuery:
    """Filter criteria for :func:`query_traces` / ``TraceStore.query``.

    Every field is optional; unset fields impose no constraint, so an empty
    :class:`TraceQuery` matches all records. Filters combine with logical AND.

    Attributes:
        principal_id: Exact principal match.
        capability_id: Exact capability match.
        event_type: Restrict to ``"invoke"`` / ``"expand"`` / ``"deny"`` events.
        outcome: ``"succeeded"`` or ``"failed"`` (by presence of ``error``).
        reason_code: Exact denial reason-code match (matches ``"deny"`` events).
        since: Lower bound on ``invoked_at``, **inclusive**.
        until: Upper bound on ``invoked_at``, **exclusive**.
        limit: Maximum number of records to return after ordering. ``None``
            means no limit; ``0`` returns an empty list.
        offset: Number of leading records to skip after ordering (for pagination).
    """

    principal_id: str | None = None
    capability_id: str | None = None
    event_type: TraceEventType | None = None
    outcome: Outcome | None = None
    reason_code: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int | None = None
    offset: int = 0


def _as_utc(value: datetime) -> datetime:
    """Treat a naive datetime as UTC (matching the rest of the codebase).

    ``ActionTrace.invoked_at`` is always timezone-aware, so comparing a naive
    bound (common when parsing user input) against it would raise ``TypeError``;
    normalising the bound to UTC avoids that surprising runtime failure.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _matches(trace: ActionTrace, query: TraceQuery) -> bool:
    """Return whether *trace* satisfies every set filter on *query*."""
    if query.principal_id is not None and trace.principal_id != query.principal_id:
        return False
    if query.capability_id is not None and trace.capability_id != query.capability_id:
        return False
    if query.event_type is not None and trace.event_type != query.event_type:
        return False
    if query.reason_code is not None and trace.reason_code != query.reason_code:
        return False
    if query.outcome is not None:
        outcome: Outcome = "failed" if trace.error is not None else "succeeded"
        if outcome != query.outcome:
            return False
    if query.since is not None and trace.invoked_at < _as_utc(query.since):
        return False
    return not (query.until is not None and trace.invoked_at >= _as_utc(query.until))


def query_traces(traces: Iterable[ActionTrace], query: TraceQuery) -> list[ActionTrace]:
    """Filter, order, and paginate *traces* per *query*.

    Args:
        traces: Records to filter (e.g. ``TraceStore.list_all()``).
        query: The filter criteria.

    Returns:
        Matching traces ordered by ``(invoked_at, action_id)``, then sliced by
        ``offset``/``limit``. The ordering is deterministic, so successive
        pages with the same query over an unchanged store are disjoint and
        jointly complete.

    Raises:
        AgentKernelError: If ``offset`` or ``limit`` is negative.
    """
    if query.offset < 0:
        raise AgentKernelError(f"TraceQuery.offset must be >= 0, got {query.offset}.")
    if query.limit is not None and query.limit < 0:
        raise AgentKernelError(f"TraceQuery.limit must be >= 0 or None, got {query.limit}.")

    matched = [trace for trace in traces if _matches(trace, query)]
    matched.sort(key=lambda trace: (trace.invoked_at, trace.action_id))

    sliced = matched[query.offset :]
    if query.limit is not None:
        sliced = sliced[: query.limit]
    return sliced


__all__ = ["Outcome", "TraceQuery", "query_traces"]
