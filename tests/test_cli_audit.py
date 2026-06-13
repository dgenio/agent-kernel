"""Tests for ``weaver-kernel audit`` (issue #147)."""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

import pytest

from weaver_kernel.cli import main
from weaver_kernel.models import ActionTrace
from weaver_kernel.stores import SQLiteTraceStore

SECRET = "cli-audit-test-secret"
BASE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def _trace(
    action_id: str, *, principal: str, error: str | None = None, day: int = 0
) -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="billing.list",
        principal_id=principal,
        token_id="tok",
        invoked_at=BASE + datetime.timedelta(days=day),
        args={},
        response_mode="summary",
        driver_id="memory",
        error=error,
    )


@pytest.fixture()
def store_path(tmp_path: Path) -> str:
    db = tmp_path / "audit.db"
    store = SQLiteTraceStore(db, secret=SECRET)
    store.record(_trace("act-a", principal="u1", day=0))
    store.record(_trace("act-b", principal="u2", day=1))
    store.record(_trace("act-c", principal="u1", error="boom", day=2))
    store.close()
    return str(db)


def test_list_shows_all(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["audit", "list", "--store", store_path, "--secret", SECRET])
    out = capsys.readouterr().out
    assert rc == 0
    assert "act-a" in out and "act-b" in out and "act-c" in out


def test_list_json(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["audit", "list", "--store", store_path, "--secret", SECRET, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert {row["action_id"] for row in data} == {"act-a", "act-b", "act-c"}


def test_list_filter_by_principal(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    main(["audit", "list", "--store", store_path, "--secret", SECRET, "--principal", "u1"])
    out = capsys.readouterr().out
    assert "act-a" in out and "act-c" in out and "act-b" not in out


def test_list_filter_by_status_failed(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    main(["audit", "list", "--store", store_path, "--secret", SECRET, "--status", "failed"])
    out = capsys.readouterr().out
    assert "act-c" in out and "act-a" not in out


def test_show(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["audit", "show", "act-b", "--store", store_path, "--secret", SECRET])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["action_id"] == "act-b"
    assert payload["principal_id"] == "u2"


def test_show_unknown_exits_nonzero(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["audit", "show", "nope", "--store", store_path, "--secret", SECRET])
    assert rc == 1
    assert "nope" in capsys.readouterr().err


def test_verify_ok(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["audit", "verify", "--store", store_path, "--secret", SECRET])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_verify_detects_tamper(store_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    conn = sqlite3.connect(store_path)
    conn.execute(
        "UPDATE traces SET payload = ? WHERE action_id = ?",
        ('{"action_id":"act-a","tampered":true}', "act-a"),
    )
    conn.commit()
    conn.close()
    rc = main(["audit", "verify", "--store", store_path, "--secret", SECRET])
    assert rc == 1
    assert "TAMPER" in capsys.readouterr().out


def test_export_to_file(store_path: str, tmp_path: Path) -> None:
    out = tmp_path / "export.jsonl"
    rc = main(["audit", "export", "--store", store_path, "--secret", SECRET, "--out", str(out)])
    assert rc == 0
    lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 3
    assert json.loads(lines[0])["action_id"] == "act-a"
