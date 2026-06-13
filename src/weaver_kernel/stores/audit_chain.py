"""Hash-chained, verifiable audit-log envelope for persisted traces (issue #127).

Each persisted :class:`~weaver_kernel.models.ActionTrace` is wrapped in a
:class:`TraceRecord` that carries the hash of the previous record. The chain is
keyed by the same HMAC secret used for token signing
(:data:`~weaver_kernel._secrets.SECRET_ENV_VAR`), so any insertion, deletion,
mutation, or reordering of records is detectable by :func:`verify_chain`.

Integrity model (honest scope): this gives **tamper-evidence** against post-hoc
edits by anyone who does not hold the secret. It is **not** non-repudiation — a
host that controls ``WEAVER_KERNEL_SECRET`` can forge a self-consistent chain.
See ``docs/security.md``.

The chaining envelope is intentionally separate from ``ActionTrace`` semantics:
``prev_hash``/``record_hash``/``seq`` live only on the persisted record, never on
the in-memory trace. The wrapped ``trace`` payload is the redaction-safe
:func:`~weaver_kernel.export_action_trace` shape, so chaining adds no field the
trace did not already hold and cannot widen the I-01 boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

CHAIN_VERSION = "1"
"""Bumped only on a breaking change to the record-hash computation."""

GENESIS_HASH = "0" * 64
"""``prev_hash`` of the first record in a chain (and of the first record after a
pruning checkpoint when no checkpoint hash is carried)."""


def canonical_json(obj: Any) -> str:
    """Serialise *obj* deterministically (sorted keys, no whitespace).

    Determinism is required so a record hashes identically across processes and
    Python versions — consistent with the repo's "no randomness in matching"
    rule.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_record_hash(
    seq: int,
    prev_hash: str,
    trace: dict[str, Any],
    *,
    secret: str,
) -> str:
    """Return the HMAC-SHA256 hex digest binding *seq*, *prev_hash*, and *trace*.

    Args:
        seq: Monotonic 0-based position of the record in the chain.
        prev_hash: ``record_hash`` of the preceding record (or the genesis /
            checkpoint hash for the first record).
        trace: The redaction-safe exported-trace payload.
        secret: HMAC key.

    Returns:
        A 64-character lowercase hex digest.
    """
    message = canonical_json({"seq": seq, "prev_hash": prev_hash, "trace": trace})
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


@dataclass(slots=True)
class TraceRecord:
    """A persisted trace plus its position and hash linkage in the audit chain."""

    seq: int
    prev_hash: str
    record_hash: str
    trace: dict[str, Any]


def build_record(
    seq: int,
    prev_hash: str,
    trace: dict[str, Any],
    *,
    secret: str,
) -> TraceRecord:
    """Construct the next :class:`TraceRecord` with a freshly computed hash."""
    record_hash = compute_record_hash(seq, prev_hash, trace, secret=secret)
    return TraceRecord(seq=seq, prev_hash=prev_hash, record_hash=record_hash, trace=trace)


@dataclass(slots=True)
class ChainVerificationResult:
    """Outcome of :func:`verify_chain`."""

    ok: bool
    """``True`` iff every record links and hashes correctly."""

    records_checked: int
    """Number of records examined before stopping."""

    first_bad_seq: int | None
    """``seq`` of the first divergent record, or ``None`` when ``ok`` is True."""

    detail: str
    """Human-readable description of the result (or the first failure)."""


def verify_chain(
    records: Sequence[TraceRecord],
    *,
    secret: str,
    genesis_prev_hash: str = GENESIS_HASH,
) -> ChainVerificationResult:
    """Verify the integrity of an ordered sequence of trace records.

    Detects mutation (recomputed hash differs), insertion/deletion/reordering
    (broken ``prev_hash`` linkage or non-contiguous ``seq``), and a wrong secret
    (every hash diverges). Records must be supplied in ascending ``seq`` order.

    Args:
        records: The chain to verify, ordered by ``seq``.
        secret: The HMAC key the records were written with.
        genesis_prev_hash: Expected ``prev_hash`` of the first record. Defaults
            to :data:`GENESIS_HASH`; a pruned store passes its checkpoint hash so
            the retained suffix still verifies.

    Returns:
        A :class:`ChainVerificationResult`.
    """
    expected_prev = genesis_prev_hash
    expected_seq = records[0].seq if records else 0
    for checked, record in enumerate(records, start=1):
        if record.seq != expected_seq:
            return ChainVerificationResult(
                ok=False,
                records_checked=checked,
                first_bad_seq=record.seq,
                detail=(
                    f"Non-contiguous sequence at position {checked}: expected seq "
                    f"{expected_seq}, found {record.seq} (insertion, deletion, or reorder)."
                ),
            )
        if not hmac.compare_digest(record.prev_hash, expected_prev):
            return ChainVerificationResult(
                ok=False,
                records_checked=checked,
                first_bad_seq=record.seq,
                detail=(
                    f"Broken link at seq {record.seq}: prev_hash does not match the "
                    "preceding record's hash (insertion, deletion, or reorder)."
                ),
            )
        recomputed = compute_record_hash(record.seq, record.prev_hash, record.trace, secret=secret)
        if not hmac.compare_digest(recomputed, record.record_hash):
            return ChainVerificationResult(
                ok=False,
                records_checked=checked,
                first_bad_seq=record.seq,
                detail=(
                    f"Tampered record at seq {record.seq}: content does not match its "
                    "stored hash (mutation, or wrong secret)."
                ),
            )
        expected_prev = record.record_hash
        expected_seq = record.seq + 1
    return ChainVerificationResult(
        ok=True,
        records_checked=len(records),
        first_bad_seq=None,
        detail=f"Verified {len(records)} record(s).",
    )
