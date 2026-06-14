"""SQLite-backed durable stores (issue #126) with audit-chain integrity (#127).

Uses the standard-library :mod:`sqlite3` only — no new runtime dependency. Each
store opens a single-file database; pass ``":memory:"`` for an ephemeral one
(useful in tests).

* :class:`SQLiteTraceStore` — hash-chained, verifiable audit trail that survives
  process restarts, plus retention pruning that preserves verifiability.
* :class:`SQLiteRevocationStore` — durable token revocation so ``revoke()`` /
  ``revoke_all()`` outlive a restart and apply across processes.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .._secrets import resolve_hmac_secret
from ..errors import AgentKernelError
from ..models import ActionTrace
from ._trace_codec import decode_trace, encode_trace
from .audit_chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    TraceRecord,
    build_record,
    verify_chain,
)


def _loads_payload(raw: str, *, context: str) -> dict[str, Any]:
    """Parse a stored JSON payload, remapping corruption to a typed error.

    A tampered or hand-edited row must surface as :class:`AgentKernelError`
    (which the CLI renders cleanly), never as a bare ``JSONDecodeError`` /
    ``ValueError`` escaping to callers (see AGENTS.md).
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AgentKernelError(f"Corrupted trace payload {context}: {exc}.") from exc
    if not isinstance(data, dict):
        raise AgentKernelError(f"Corrupted trace payload {context}: expected a JSON object.")
    return data


class SQLiteTraceStore:
    """Durable, hash-chained :class:`TraceStoreProtocol` backend.

    The signing secret defaults to the shared ``WEAVER_KERNEL_SECRET`` path; a
    store opened with a different secret than it was written with will fail
    :meth:`verify_chain`.

    Concurrency: this store is **single-writer**. Writes are serialised within a
    process by a lock, but the chain head is read-then-written without a
    cross-process transaction, so two processes writing the same file can collide
    on ``seq`` (surfaced as :class:`AgentKernelError`) or fork the chain. Use one
    writer per store file. Durable *revocation* (:class:`SQLiteRevocationStore`)
    is safe across processes; the trace chain is not.
    """

    def __init__(self, path: str | Path, *, secret: str | None = None) -> None:
        self._secret = resolve_hmac_secret(secret)
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS traces ("
                "seq INTEGER PRIMARY KEY, "
                "action_id TEXT UNIQUE NOT NULL, "
                "prev_hash TEXT NOT NULL, "
                "record_hash TEXT NOT NULL, "
                "invoked_at TEXT NOT NULL, "
                "payload TEXT NOT NULL)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
            )
            self._conn.commit()
        except sqlite3.DatabaseError as exc:
            # e.g. pointing --store at a JSONL file: sqlite3 opens it but the
            # first statement raises "file is not a database". Surface a typed
            # error the CLI renders, not a bare traceback (see AGENTS.md).
            self._conn.close()
            raise AgentKernelError(
                f"'{self._path}' is not a valid SQLite trace store: {exc}. "
                "If this is a JSONL store, pass --format jsonl."
            ) from exc

    # ── Internal helpers ────────────────────────────────────────────────────

    def _get_meta(self, key: str, default: str) -> str:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return default if row is None else str(row[0])

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ── TraceStoreProtocol ───────────────────────────────────────────────────

    def record(self, trace: ActionTrace) -> None:
        """Append *trace* to the chain, linked to the current head."""
        payload = encode_trace(trace)
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, record_hash FROM traces ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row is not None:
                next_seq = int(row[0]) + 1
                prev_hash = str(row[1])
            else:
                next_seq = int(self._get_meta("checkpoint_next_seq", "0"))
                prev_hash = self._get_meta("checkpoint_hash", GENESIS_HASH)
            record = build_record(next_seq, prev_hash, payload, secret=self._secret)
            try:
                self._conn.execute(
                    "INSERT INTO traces "
                    "(seq, action_id, prev_hash, record_hash, invoked_at, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        record.seq,
                        trace.action_id,
                        record.prev_hash,
                        record.record_hash,
                        payload["invoked_at"],
                        json.dumps(payload),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                # Duplicate action_id (UNIQUE) or seq (PRIMARY KEY). Each
                # invocation has a fresh action_id, so this signals a re-recorded
                # trace or a concurrent second writer (the store is single-writer;
                # see the class docstring). Surface a typed error rather than let a
                # bare sqlite3.IntegrityError escape to the caller (see AGENTS.md).
                self._conn.rollback()
                raise AgentKernelError(
                    f"Cannot record trace: action_id '{trace.action_id}' is already "
                    "present in the store (duplicate record or concurrent write)."
                ) from exc

    def get(self, action_id: str) -> ActionTrace:
        """Return the trace for *action_id*."""
        row = self._conn.execute(
            "SELECT payload FROM traces WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise AgentKernelError(f"No action trace found for action_id='{action_id}'.")
        return decode_trace(_loads_payload(row[0], context=f"for action_id='{action_id}'"))

    def list_all(self) -> list[ActionTrace]:
        """Return all traces in chain order."""
        rows = self._conn.execute("SELECT seq, payload FROM traces ORDER BY seq").fetchall()
        return [
            decode_trace(_loads_payload(r[1], context=f"at seq {int(r[0])} in {self._path}"))
            for r in rows
        ]

    # ── Audit chain (issue #127) ──────────────────────────────────────────────

    def list_records(self) -> list[TraceRecord]:
        """Return the raw chain records in ``seq`` order (for export/verify)."""
        rows = self._conn.execute(
            "SELECT seq, prev_hash, record_hash, payload FROM traces ORDER BY seq"
        ).fetchall()
        return [
            TraceRecord(
                seq=int(r[0]),
                prev_hash=str(r[1]),
                record_hash=str(r[2]),
                trace=_loads_payload(r[3], context=f"at seq {int(r[0])} in {self._path}"),
            )
            for r in rows
        ]

    def verify_chain(self) -> ChainVerificationResult:
        """Verify the full chain, honouring any pruning checkpoint."""
        genesis = self._get_meta("checkpoint_hash", GENESIS_HASH)
        return verify_chain(self.list_records(), secret=self._secret, genesis_prev_hash=genesis)

    def prune(self, before: datetime.datetime) -> int:
        """Delete records older than *before*, preserving suffix verifiability.

        The ``record_hash`` of the last pruned record is stored as the chain
        checkpoint, so :meth:`verify_chain` still validates the retained suffix.

        Args:
            before: Cutoff; records with ``invoked_at`` strictly before this are
                removed. Normalised to UTC before comparison (a naive datetime is
                assumed to be UTC) so the lexicographic comparison against the
                stored UTC ISO-8601 timestamps is correct.

        Returns:
            The number of records pruned.
        """
        if before.tzinfo is None:
            before = before.replace(tzinfo=datetime.timezone.utc)
        cutoff = before.astimezone(datetime.timezone.utc).isoformat()
        with self._lock:
            doomed = self._conn.execute(
                "SELECT seq, record_hash FROM traces WHERE invoked_at < ? ORDER BY seq",
                (cutoff,),
            ).fetchall()
            if not doomed:
                return 0
            last_seq, last_hash = int(doomed[-1][0]), str(doomed[-1][1])
            self._conn.execute("DELETE FROM traces WHERE invoked_at < ?", (cutoff,))
            self._set_meta("checkpoint_hash", last_hash)
            self._set_meta("checkpoint_next_seq", str(last_seq + 1))
            self._conn.commit()
            return len(doomed)

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()


class SQLiteRevocationStore:
    """Durable :class:`RevocationStoreProtocol` backend.

    A token revoked here stays revoked after a process restart and is visible to
    every process sharing the database file.
    """

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS revoked (token_id TEXT PRIMARY KEY)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS principal_tokens ("
            "principal_id TEXT NOT NULL, token_id TEXT NOT NULL, "
            "PRIMARY KEY (principal_id, token_id))"
        )
        self._conn.commit()

    def is_revoked(self, token_id: str) -> bool:
        """Return whether *token_id* has been revoked."""
        row = self._conn.execute(
            "SELECT 1 FROM revoked WHERE token_id = ?", (token_id,)
        ).fetchone()
        return row is not None

    def revoke(self, token_id: str) -> None:
        """Revoke a single token. Idempotent."""
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO revoked (token_id) VALUES (?)", (token_id,))
            self._conn.commit()

    def track(self, principal_id: str, token_id: str) -> None:
        """Record that *token_id* was issued to *principal_id*."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO principal_tokens (principal_id, token_id) VALUES (?, ?)",
                (principal_id, token_id),
            )
            self._conn.commit()

    def revoke_principal(self, principal_id: str) -> int:
        """Revoke every tracked token for *principal_id*.

        Returns:
            The count of tokens newly revoked by this call.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT token_id FROM principal_tokens WHERE principal_id = ?",
                (principal_id,),
            ).fetchall()
            token_ids = {str(r[0]) for r in rows}
            newly = {
                tid
                for tid in token_ids
                if self._conn.execute(
                    "SELECT 1 FROM revoked WHERE token_id = ?", (tid,)
                ).fetchone()
                is None
            }
            self._conn.executemany(
                "INSERT OR IGNORE INTO revoked (token_id) VALUES (?)",
                [(tid,) for tid in newly],
            )
            self._conn.execute(
                "DELETE FROM principal_tokens WHERE principal_id = ?", (principal_id,)
            )
            self._conn.commit()
            return len(newly)

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
