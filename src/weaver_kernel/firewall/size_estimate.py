"""Allocation-free payload size estimation for the firewall hot path.

``estimated_size`` approximates ``len(json.dumps(value, default=str))`` by
walking the structure and summing approximate character contributions, *without*
serialising the value to an intermediate string. The firewall runs on every
egress path and only needs the size to compare against budget thresholds, so a
single allocation-free pass (with an optional early exit) replaces a full JSON
serialisation that would double peak memory on large payloads.

The estimate is intentionally approximate but **deterministic**: the same input
always yields the same number (the total is order-independent). Self-referential
structures are handled gracefully — each container is counted at most once, so a
cycle can never hang the walk (unlike ``json.dumps``, which raises). It is used
both by
:mod:`~weaver_kernel.firewall.transform` (raw-mode budget warning, issue #207)
and by :class:`~weaver_kernel.handles.HandleStore` (byte-size budgeting,
issue #211).
"""

from __future__ import annotations

from typing import Any

# Approximate JSON literal widths and structural overhead. json.dumps with the
# default separators emits ``", "`` between items and ``": "`` between a key and
# its value; object/array delimiters add two characters per container. These
# constants keep the estimate close to the real serialised length without
# reproducing json's exact escaping rules (bounded error is acceptable because
# only threshold comparisons depend on the result).
_NULL_LEN = 4  # "null"
_TRUE_LEN = 4  # "true"
_FALSE_LEN = 5  # "false"
_QUOTES = 2  # surrounding "" on a string
_CONTAINER_DELIMS = 2  # {} or []
_ITEM_SEP = 2  # ", "
_KV_SEP = 2  # ": "


def estimated_size(value: Any, *, limit: int | None = None) -> int:
    """Approximate the serialised character size of *value* without serialising.

    Walks *value* iteratively (so deeply nested structures cannot exhaust the
    recursion limit) summing approximate JSON character contributions. ``bool``
    is handled before ``int`` because ``bool`` is an ``int`` subclass in Python.
    Each container is visited at most once, so self-referential inputs terminate
    instead of looping forever.

    Args:
        value: Any value the firewall might serialise. Non-JSON types fall back
            to ``len(str(value))`` plus string quoting, mirroring the
            ``default=str`` behaviour of the previous ``json.dumps`` measurement.
        limit: Optional early-exit threshold. When the running total exceeds
            *limit* the walk stops and returns a value greater than *limit* — use
            this when only the boolean ``size > limit`` decision is needed, not
            the exact size. (Which member tips the total past *limit* is
            unspecified, but the returned value is always ``> limit``.)

    Returns:
        A non-negative integer approximating ``len(json.dumps(value,
        default=str))``.

    Example:
        >>> estimated_size(None)
        4
        >>> estimated_size("hi")
        4
        >>> estimated_size([1, 2, 3])
        9
    """
    total = 0
    seen: set[int] = set()  # container ids already counted, to break cycles
    stack: list[Any] = [value]
    while stack:
        cur = stack.pop()
        if cur is None:
            total += _NULL_LEN
        elif cur is True:
            total += _TRUE_LEN
        elif cur is False:
            total += _FALSE_LEN
        elif isinstance(cur, str):
            total += len(cur) + _QUOTES
        elif isinstance(cur, bool):  # pragma: no cover - True/False caught above
            total += _TRUE_LEN
        elif isinstance(cur, (int, float)):
            total += len(str(cur))
        elif isinstance(cur, dict):
            if id(cur) in seen:
                continue
            seen.add(id(cur))
            n = len(cur)
            total += _CONTAINER_DELIMS + max(0, n - 1) * _ITEM_SEP
            for key, val in cur.items():
                total += len(str(key)) + _QUOTES + _KV_SEP
                stack.append(val)
        elif isinstance(cur, (list, tuple)):
            if id(cur) in seen:
                continue
            seen.add(id(cur))
            n = len(cur)
            total += _CONTAINER_DELIMS + max(0, n - 1) * _ITEM_SEP
            stack.extend(cur)
        else:
            # Mirrors json.dumps(default=str): rendered as a quoted string.
            total += len(str(cur)) + _QUOTES
        if limit is not None and total > limit:
            return total
    return total
