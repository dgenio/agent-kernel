"""Tests for the SQLite durable stores (issues #126, #127)."""

from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

import pytest

from weaver_kernel import HMACTokenProvider
from weaver_kernel.errors import AgentKernelError, TokenRevoked
from weaver_kernel.models import ActionTrace
from weaver_kernel.stores import SQLiteRevocationStore, SQLiteTraceStore

SECRET = "sqlite-store-test-secret"


def _trace(action_id: str, *, when: datetime.datetime | None = None) -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="billing.list",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=when or datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        args={"a": 1},
        response_mode="summary",
        driver_id="memory",
    )


# ── SQLiteTraceStore ─────────────────────────────────────────────────────────


def test_record_get_and_list(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    assert store.get("act-0").action_id == "act-0"
    assert [t.action_id for t in store.list_all()] == ["act-0", "act-1"]


def test_get_unknown_raises(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    with pytest.raises(AgentKernelError, match="act-missing"):
        store.get("act-missing")


def test_round_trip_preserves_fields(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    store.record(_trace("act-rt"))
    got = store.get("act-rt")
    assert got.args == {"a": 1}
    assert got.invoked_at == datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    assert got.driver_id == "memory"


def test_persistence_survives_reopen(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    first = SQLiteTraceStore(db, secret=SECRET)
    first.record(_trace("act-0"))
    first.close()
    reopened = SQLiteTraceStore(db, secret=SECRET)
    assert [t.action_id for t in reopened.list_all()] == ["act-0"]
    assert reopened.verify_chain().ok


def test_chain_verifies_and_continues_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    first = SQLiteTraceStore(db, secret=SECRET)
    first.record(_trace("act-0"))
    first.close()
    reopened = SQLiteTraceStore(db, secret=SECRET)
    reopened.record(_trace("act-1"))
    records = reopened.list_records()
    assert [r.seq for r in records] == [0, 1]
    assert reopened.verify_chain().ok


def test_tamper_with_db_row_detected(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    store = SQLiteTraceStore(db, secret=SECRET)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    store.close()
    # Mutate a stored payload directly, leaving record_hash untouched.
    conn = sqlite3.connect(str(db))
    conn.execute(
        "UPDATE traces SET payload = ? WHERE action_id = ?",
        ('{"action_id":"act-0","tampered":true}', "act-0"),
    )
    conn.commit()
    conn.close()
    result = SQLiteTraceStore(db, secret=SECRET).verify_chain()
    assert not result.ok
    assert result.first_bad_seq == 0


def test_wrong_secret_fails_verification(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    SQLiteTraceStore(db, secret=SECRET).record(_trace("act-0"))
    assert not SQLiteTraceStore(db, secret="other-secret").verify_chain().ok


def test_prune_preserves_suffix_verifiability(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for i in range(5):
        store.record(_trace(f"act-{i}", when=base + datetime.timedelta(days=i)))
    pruned = store.prune(before=base + datetime.timedelta(days=2))
    assert pruned == 2
    assert [t.action_id for t in store.list_all()] == ["act-2", "act-3", "act-4"]
    assert store.verify_chain().ok


def test_prune_then_append_keeps_chain_verifiable(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for i in range(3):
        store.record(_trace(f"act-{i}", when=base + datetime.timedelta(days=i)))
    store.prune(before=base + datetime.timedelta(days=1))
    store.record(_trace("act-new", when=base + datetime.timedelta(days=9)))
    assert store.verify_chain().ok
    assert [r.seq for r in store.list_records()] == [1, 2, 3]


def test_prune_nothing_returns_zero(tmp_path: Path) -> None:
    store = SQLiteTraceStore(tmp_path / "a.db", secret=SECRET)
    store.record(_trace("act-0"))
    assert store.prune(before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)) == 0


# ── SQLiteRevocationStore ──────────────────────────────────────────────────────


def test_revocation_basic(tmp_path: Path) -> None:
    store = SQLiteRevocationStore(tmp_path / "r.db")
    assert not store.is_revoked("t1")
    store.revoke("t1")
    assert store.is_revoked("t1")
    store.revoke("t1")  # idempotent


def test_revoke_principal_counts_only_newly_revoked(tmp_path: Path) -> None:
    store = SQLiteRevocationStore(tmp_path / "r.db")
    store.track("p1", "t1")
    store.track("p1", "t2")
    store.revoke("t1")
    assert store.revoke_principal("p1") == 1  # only t2 newly revoked
    assert store.is_revoked("t2")


def test_revocation_survives_reopen(tmp_path: Path) -> None:
    db = tmp_path / "r.db"
    first = SQLiteRevocationStore(db)
    first.revoke("t1")
    first.close()
    assert SQLiteRevocationStore(db).is_revoked("t1")


def test_revoked_token_stays_revoked_for_fresh_provider(tmp_path: Path) -> None:
    """Issue #126 acceptance: revocation outlives the provider instance."""
    db = tmp_path / "r.db"
    provider = HMACTokenProvider(secret=SECRET, revocation_store=SQLiteRevocationStore(db))
    token = provider.issue("cap.x", "u1")
    provider.revoke(token.token_id)

    fresh = HMACTokenProvider(secret=SECRET, revocation_store=SQLiteRevocationStore(db))
    with pytest.raises(TokenRevoked, match="revoked"):
        fresh.verify(token, expected_principal_id="u1", expected_capability_id="cap.x")
