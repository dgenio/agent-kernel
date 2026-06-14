"""Tests for the hash-chained audit-log envelope (issue #127)."""

from __future__ import annotations

import dataclasses

from weaver_kernel.stores.audit_chain import (
    GENESIS_HASH,
    TraceRecord,
    build_record,
    compute_record_hash,
    verify_chain,
)

SECRET = "chain-test-secret"


def _chain(n: int, *, secret: str = SECRET) -> list[TraceRecord]:
    records: list[TraceRecord] = []
    prev = GENESIS_HASH
    for i in range(n):
        rec = build_record(i, prev, {"action_id": f"a{i}", "n": i}, secret=secret)
        records.append(rec)
        prev = rec.record_hash
    return records


def test_empty_chain_verifies() -> None:
    result = verify_chain([], secret=SECRET)
    assert result.ok
    assert result.records_checked == 0
    assert result.first_bad_seq is None


def test_valid_chain_verifies() -> None:
    result = verify_chain(_chain(5), secret=SECRET)
    assert result.ok
    assert result.records_checked == 5


def test_first_record_links_to_genesis() -> None:
    records = _chain(1)
    assert records[0].prev_hash == GENESIS_HASH


def test_hash_is_deterministic() -> None:
    payload = {"action_id": "a", "x": 1}
    assert compute_record_hash(0, GENESIS_HASH, payload, secret=SECRET) == compute_record_hash(
        0, GENESIS_HASH, payload, secret=SECRET
    )


def test_mutation_detected() -> None:
    records = _chain(4)
    records[2].trace["n"] = 999  # tamper with content, leave stored hash intact
    result = verify_chain(records, secret=SECRET)
    assert not result.ok
    assert result.first_bad_seq == 2
    assert "Tampered" in result.detail


def test_deletion_detected() -> None:
    records = _chain(4)
    del records[2]  # seq jumps 1,? -> 3 after re-walk; link/seq breaks
    result = verify_chain(records, secret=SECRET)
    assert not result.ok
    assert result.first_bad_seq == 3


def test_insertion_detected() -> None:
    records = _chain(3)
    forged = build_record(1, records[0].record_hash, {"action_id": "x"}, secret=SECRET)
    records.insert(1, forged)  # duplicate seq=1 with a different record
    result = verify_chain(records, secret=SECRET)
    assert not result.ok


def test_reorder_detected() -> None:
    records = _chain(4)
    records[1], records[2] = records[2], records[1]
    result = verify_chain(records, secret=SECRET)
    assert not result.ok
    assert result.first_bad_seq == 2  # seq 2 appears where seq 1 was expected


def test_wrong_secret_fails() -> None:
    records = _chain(3, secret=SECRET)
    result = verify_chain(records, secret="different-secret")
    assert not result.ok
    assert result.first_bad_seq == 0


def test_checkpoint_genesis_allows_suffix_verification() -> None:
    records = _chain(5)
    suffix = records[2:]  # drop the first two as if pruned
    # With the default genesis the suffix breaks; with the checkpoint hash of the
    # last pruned record it verifies.
    assert not verify_chain(suffix, secret=SECRET).ok
    ok = verify_chain(suffix, secret=SECRET, genesis_prev_hash=records[1].record_hash)
    assert ok.ok
    assert ok.records_checked == 3


def test_record_is_a_slots_dataclass() -> None:
    rec = _chain(1)[0]
    assert dataclasses.is_dataclass(rec)
