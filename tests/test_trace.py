"""Tests for TraceStore."""

from __future__ import annotations

import datetime

import pytest

from agent_kernel import TraceStore
from agent_kernel.errors import AgentKernelError
from agent_kernel.models import ActionTrace


def _trace(action_id: str = "act-1") -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="cap.x",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
        args={"a": 1},
        response_mode="summary",
        driver_id="memory",
    )


def test_record_and_get() -> None:
    store = TraceStore()
    t = _trace("act-1")
    store.record(t)
    result = store.get("act-1")
    assert result is t


def test_get_unknown_raises() -> None:
    store = TraceStore()
    with pytest.raises(AgentKernelError, match="act-missing"):
        store.get("act-missing")


def test_list_all() -> None:
    store = TraceStore()
    for i in range(3):
        store.record(_trace(f"act-{i}"))
    all_traces = store.list_all()
    assert len(all_traces) == 3
    assert [t.action_id for t in all_traces] == ["act-0", "act-1", "act-2"]


def test_explain_returns_consistent_data() -> None:
    store = TraceStore()
    t = _trace("act-explain")
    store.record(t)
    result = store.get("act-explain")
    assert result.capability_id == "cap.x"
    assert result.principal_id == "u1"
    assert result.driver_id == "memory"
    assert result.args == {"a": 1}
