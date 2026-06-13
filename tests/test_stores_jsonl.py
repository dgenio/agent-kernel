"""Tests for the append-only JSONL trace store (issues #126, #127)."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from weaver_kernel.errors import AgentKernelError
from weaver_kernel.models import ActionTrace
from weaver_kernel.stores import JsonlTraceStore

SECRET = "jsonl-store-test-secret"


def _trace(action_id: str) -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="billing.list",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        args={"a": 1},
        response_mode="summary",
        driver_id="memory",
    )


def test_record_get_and_list(tmp_path: Path) -> None:
    store = JsonlTraceStore(tmp_path / "a.jsonl", secret=SECRET)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    assert store.get("act-1").action_id == "act-1"
    assert [t.action_id for t in store.list_all()] == ["act-0", "act-1"]


def test_get_unknown_raises(tmp_path: Path) -> None:
    store = JsonlTraceStore(tmp_path / "a.jsonl", secret=SECRET)
    with pytest.raises(AgentKernelError, match="act-missing"):
        store.get("act-missing")


def test_one_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    store = JsonlTraceStore(path, secret=SECRET)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2


def test_chain_verifies(tmp_path: Path) -> None:
    store = JsonlTraceStore(tmp_path / "a.jsonl", secret=SECRET)
    for i in range(3):
        store.record(_trace(f"act-{i}"))
    assert store.verify_chain().ok


def test_resume_chain_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    first = JsonlTraceStore(path, secret=SECRET)
    first.record(_trace("act-0"))
    reopened = JsonlTraceStore(path, secret=SECRET)
    reopened.record(_trace("act-1"))
    assert [r.seq for r in reopened.list_records()] == [0, 1]
    assert reopened.verify_chain().ok


def test_tampered_line_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    store = JsonlTraceStore(path, secret=SECRET)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert '"a": 1' in lines[0]
    lines[0] = lines[0].replace('"a": 1', '"a": 999')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = JsonlTraceStore(path, secret=SECRET).verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 0


def test_blank_lines_ignored(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    store = JsonlTraceStore(path, secret=SECRET)
    store.record(_trace("act-0"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")
    assert len(JsonlTraceStore(path, secret=SECRET).list_all()) == 1
