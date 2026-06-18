"""Tests for the TraceStore query API (issue #177)."""

from __future__ import annotations

import datetime

import pytest

from weaver_kernel import TraceQuery, TraceStore, query_traces
from weaver_kernel.errors import AgentKernelError
from weaver_kernel.models import ActionTrace

_BASE = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _trace(
    action_id: str,
    *,
    principal_id: str = "p1",
    capability_id: str = "cap.a",
    minute: int = 0,
    event_type: str = "invoke",
    reason_code: str | None = None,
    error: str | None = None,
) -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id=capability_id,
        principal_id=principal_id,
        token_id="tok",
        invoked_at=_BASE + datetime.timedelta(minutes=minute),
        args={},
        response_mode="summary",
        driver_id="d",
        event_type=event_type,  # type: ignore[arg-type]
        reason_code=reason_code,
        error=error,
    )


def _corpus() -> list[ActionTrace]:
    return [
        _trace("a1", principal_id="alice", capability_id="cap.read", minute=0),
        _trace("a2", principal_id="bob", capability_id="cap.read", minute=1),
        _trace("a3", principal_id="alice", capability_id="cap.write", minute=2, error="boom"),
        _trace(
            "a4",
            principal_id="alice",
            capability_id="cap.write",
            minute=3,
            event_type="deny",
            reason_code="missing_role",
            error="denied: missing role",
        ),
        _trace(
            "a5", principal_id="alice", capability_id="cap.read", minute=4, event_type="expand"
        ),
    ]


def test_empty_query_matches_all() -> None:
    result = query_traces(_corpus(), TraceQuery())
    assert [t.action_id for t in result] == ["a1", "a2", "a3", "a4", "a5"]


def test_filter_by_principal() -> None:
    result = query_traces(_corpus(), TraceQuery(principal_id="alice"))
    assert [t.action_id for t in result] == ["a1", "a3", "a4", "a5"]


def test_filter_by_capability() -> None:
    result = query_traces(_corpus(), TraceQuery(capability_id="cap.write"))
    assert {t.action_id for t in result} == {"a3", "a4"}


def test_filter_by_event_type() -> None:
    assert [t.action_id for t in query_traces(_corpus(), TraceQuery(event_type="deny"))] == ["a4"]
    assert [t.action_id for t in query_traces(_corpus(), TraceQuery(event_type="expand"))] == [
        "a5"
    ]


def test_filter_by_outcome() -> None:
    succeeded = query_traces(_corpus(), TraceQuery(outcome="succeeded"))
    failed = query_traces(_corpus(), TraceQuery(outcome="failed"))
    assert {t.action_id for t in succeeded} == {"a1", "a2", "a5"}
    assert {t.action_id for t in failed} == {"a3", "a4"}


def test_filter_by_reason_code() -> None:
    result = query_traces(_corpus(), TraceQuery(reason_code="missing_role"))
    assert [t.action_id for t in result] == ["a4"]


def test_filter_by_time_window_since_inclusive_until_exclusive() -> None:
    # since is inclusive (minute 1), until is exclusive (minute 3) → a2, a3 only.
    result = query_traces(
        _corpus(),
        TraceQuery(
            since=_BASE + datetime.timedelta(minutes=1),
            until=_BASE + datetime.timedelta(minutes=3),
        ),
    )
    assert [t.action_id for t in result] == ["a2", "a3"]


def test_combination_filters_are_anded() -> None:
    result = query_traces(
        _corpus(), TraceQuery(principal_id="alice", capability_id="cap.read", outcome="succeeded")
    )
    assert [t.action_id for t in result] == ["a1", "a5"]


def test_ordering_is_deterministic_by_time_then_action_id() -> None:
    # Two traces at the same instant must order by action_id.
    same = [
        _trace("zzz", minute=5),
        _trace("aaa", minute=5),
    ]
    result = query_traces(same, TraceQuery())
    assert [t.action_id for t in result] == ["aaa", "zzz"]


def test_pagination_slices_are_disjoint_and_complete() -> None:
    corpus = _corpus()
    page1 = query_traces(corpus, TraceQuery(limit=2, offset=0))
    page2 = query_traces(corpus, TraceQuery(limit=2, offset=2))
    page3 = query_traces(corpus, TraceQuery(limit=2, offset=4))
    ids = [t.action_id for t in page1 + page2 + page3]
    assert ids == ["a1", "a2", "a3", "a4", "a5"]  # disjoint + complete, in order


def test_limit_zero_returns_empty() -> None:
    assert query_traces(_corpus(), TraceQuery(limit=0)) == []


def test_negative_offset_raises() -> None:
    with pytest.raises(AgentKernelError, match="offset must be >= 0"):
        query_traces(_corpus(), TraceQuery(offset=-1))


def test_negative_limit_raises() -> None:
    with pytest.raises(AgentKernelError, match="limit must be >= 0"):
        query_traces(_corpus(), TraceQuery(limit=-5))


def test_empty_store_yields_empty() -> None:
    assert query_traces([], TraceQuery(principal_id="alice")) == []


def test_trace_store_query_integration() -> None:
    store = TraceStore()
    for trace in _corpus():
        store.record(trace)
    result = store.query(TraceQuery(principal_id="alice", event_type="invoke"))
    assert [t.action_id for t in result] == ["a1", "a3"]
