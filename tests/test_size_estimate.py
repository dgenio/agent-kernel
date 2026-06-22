"""Tests for the allocation-free size estimator (issue #207)."""

from __future__ import annotations

import datetime
import json

import pytest

from weaver_kernel.firewall.size_estimate import estimated_size


def _json_len(value: object) -> int:
    return len(json.dumps(value, default=str))


def test_scalars() -> None:
    assert estimated_size(None) == 4
    assert estimated_size(True) == 4
    assert estimated_size(False) == 5
    assert estimated_size("hi") == 4  # 2 chars + 2 quotes
    assert estimated_size(12345) == 5


def test_matches_json_dumps_on_simple_containers() -> None:
    # For containers of scalars the estimate is exact against json.dumps.
    for value in ([1, 2, 3], {"a": 1, "b": 2}, [], {}, ["x", "y"]):
        assert estimated_size(value) == _json_len(value), value


@pytest.mark.parametrize(
    "value",
    [
        {"rows": [{"id": i, "name": f"n{i}", "active": i % 2 == 0} for i in range(50)]},
        [{"k": "v" * 100} for _ in range(20)],
        {"nested": {"deep": {"deeper": ["a", "b", "c"]}}},
        {"when": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)},
        "x" * 5000,
    ],
)
def test_bounded_error_against_json(value: object) -> None:
    # The estimate need not be exact (it does not reproduce JSON escaping), but
    # it must track json.dumps closely enough that budget threshold comparisons
    # do not flip: stay within ±25% of the real serialised length.
    actual = _json_len(value)
    estimate = estimated_size(value)
    assert 0.75 * actual <= estimate <= 1.25 * actual, (actual, estimate)


def test_early_exit_stops_past_limit() -> None:
    big = {"payload": "x" * 100_000}
    # With a small limit the walk returns as soon as it crosses the threshold,
    # so the reported value need only be greater than the limit.
    assert estimated_size(big, limit=100) > 100


def test_non_serialisable_falls_back_to_str() -> None:
    class Opaque:
        def __str__(self) -> str:
            return "opaque-value"

    # Mirrors the previous json.dumps(default=str): rendered as a quoted string.
    assert estimated_size(Opaque()) == len("opaque-value") + 2


def test_deeply_nested_does_not_recurse() -> None:
    value: object = "leaf"
    for _ in range(5000):
        value = [value]
    # Iterative walk: no RecursionError even far past the recursion limit.
    assert estimated_size(value) > 5000
