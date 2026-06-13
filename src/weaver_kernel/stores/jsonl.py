"""Append-only JSONL trace store (issue #126), hash-chained (#127).

One JSON object per line — ``{"seq", "prev_hash", "record_hash", "trace"}`` —
so the file is safe to ship to a log collector and replay-loadable. The chain
links exactly as in :class:`~weaver_kernel.stores.SQLiteTraceStore`; verification
uses the genesis hash (JSONL is append-only and does not prune — rotate the file
externally if needed).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

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


class JsonlTraceStore:
    """Durable append-only :class:`TraceStoreProtocol` backend."""

    def __init__(self, path: str | Path, *, secret: str | None = None) -> None:
        self._secret = resolve_hmac_secret(secret)
        self._path = Path(path)
        self._lock = threading.Lock()
        # Resume the chain from the file's current head, if any.
        self._next_seq = 0
        self._last_hash = GENESIS_HASH
        for record in self._iter_records():
            self._next_seq = record.seq + 1
            self._last_hash = record.record_hash

    def _iter_records(self) -> list[TraceRecord]:
        if not self._path.exists():
            return []
        records: list[TraceRecord] = []
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                records.append(
                    TraceRecord(
                        seq=int(obj["seq"]),
                        prev_hash=str(obj["prev_hash"]),
                        record_hash=str(obj["record_hash"]),
                        trace=obj["trace"],
                    )
                )
        return records

    # ── TraceStoreProtocol ───────────────────────────────────────────────────

    def record(self, trace: ActionTrace) -> None:
        """Append *trace* as a new chained line."""
        payload = encode_trace(trace)
        with self._lock:
            record = build_record(self._next_seq, self._last_hash, payload, secret=self._secret)
            line = json.dumps(
                {
                    "seq": record.seq,
                    "prev_hash": record.prev_hash,
                    "record_hash": record.record_hash,
                    "trace": record.trace,
                }
            )
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            self._next_seq = record.seq + 1
            self._last_hash = record.record_hash

    def get(self, action_id: str) -> ActionTrace:
        """Return the trace for *action_id*."""
        for record in self._iter_records():
            if record.trace.get("action_id") == action_id:
                return decode_trace(record.trace)
        raise AgentKernelError(f"No action trace found for action_id='{action_id}'.")

    def list_all(self) -> list[ActionTrace]:
        """Return all traces in append order."""
        return [decode_trace(record.trace) for record in self._iter_records()]

    # ── Audit chain (issue #127) ──────────────────────────────────────────────

    def list_records(self) -> list[TraceRecord]:
        """Return the raw chain records in append order."""
        return self._iter_records()

    def verify_chain(self) -> ChainVerificationResult:
        """Verify the full append-only chain from genesis."""
        return verify_chain(self._iter_records(), secret=self._secret)
