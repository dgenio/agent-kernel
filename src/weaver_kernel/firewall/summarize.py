"""Deterministic summarization heuristics for the context firewall.

No LLM is used — summaries are produced by structural analysis of the data.
"""

from __future__ import annotations

from itertools import islice
from typing import Any


def summarize(data: Any, *, max_facts: int = 20) -> list[str]:
    """Produce a list of human-readable facts from *data*.

    Dispatches to specialised handlers based on the type of *data*:

    - **list of dicts** → count + top keys + basic stats on numeric fields.
    - **dict** → keys + per-value type annotations + aggregates.
    - **str** → truncated string.
    - **other** → ``repr()`` truncated to 200 chars.

    Args:
        data: The data to summarise.
        max_facts: Maximum number of facts to return.

    Returns:
        An ordered list of fact strings (≤ *max_facts*).
    """
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return _summarize_list_of_dicts(data, max_facts=max_facts)
    if isinstance(data, dict):
        return _summarize_dict(data, max_facts=max_facts)
    if isinstance(data, list):
        return _summarize_plain_list(data, max_facts=max_facts)
    if isinstance(data, str):
        return _summarize_string(data, max_facts=max_facts)
    return [repr(data)[:200]]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _is_number(value: Any) -> bool:
    """True for real numbers, excluding ``bool`` (an ``int`` subclass)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _truncate_facts(facts: list[str], max_facts: int, *, total: int | None = None) -> list[str]:
    """Cap *facts* at *max_facts*, surfacing omission explicitly.

    Silent truncation lets an LLM treat a partial summary as complete. When
    facts are dropped, the final slot becomes an explicit marker stating how
    many were omitted; an untruncated list is returned unchanged so it carries
    no marker (issue #174).

    Args:
        facts: The (possibly already-bounded) candidate fact strings.
        max_facts: Maximum facts to return.
        total: True number of candidate facts when *facts* was pre-capped by the
            caller (so it never materialises one fact per item on the hot path).
            Defaults to ``len(facts)``.
    """
    if max_facts <= 0:
        return []
    candidate_total = len(facts) if total is None else total
    if candidate_total <= max_facts:
        return facts[:max_facts]
    omitted = candidate_total - (max_facts - 1)
    return [*facts[: max_facts - 1], f"… ({omitted} more facts omitted; full data via handle)"]


# ── Specialised handlers ──────────────────────────────────────────────────────


def _summarize_list_of_dicts(rows: list[dict[str, Any]], *, max_facts: int) -> list[str]:
    facts: list[str] = []
    facts.append(f"Total rows: {len(rows)}")

    # Top keys (union of keys in first 10 rows for performance)
    key_counts: dict[str, int] = {}
    for row in rows[:10]:
        for k in row:
            key_counts[k] = key_counts.get(k, 0) + 1
    top_keys = sorted(key_counts, key=lambda k: -key_counts[k])[:10]
    facts.append(f"Top keys: {', '.join(top_keys)}")

    # Numeric stats. ``bool`` is a subclass of ``int`` in Python, so a boolean
    # column would otherwise be "averaged" into a meaningless mean (e.g. the
    # mean of ``is_active`` = 0.7); exclude bools here and report them as
    # true/false counts below instead (issue #174).
    numeric_keys = [
        k
        for k in top_keys
        if all(_is_number(r.get(k)) for r in rows if k in r)
        and any(_is_number(r.get(k)) for r in rows if k in r)
    ]
    for k in numeric_keys[:5]:
        values = [float(r[k]) for r in rows if k in r]
        if values:
            facts.append(
                f"{k}: min={min(values):.2f}, max={max(values):.2f}, "
                f"avg={sum(values) / len(values):.2f}"
            )

    # Categorical / boolean counts for the remaining string-or-bool columns.
    for k in top_keys[:5]:
        if k in numeric_keys:
            continue
        present = [r[k] for r in rows if k in r]
        bool_vals = [v for v in present if isinstance(v, bool)]
        if bool_vals and len(bool_vals) == len(present):
            true_count = sum(1 for v in bool_vals if v)
            facts.append(f"{k}: True={true_count}, False={len(bool_vals) - true_count}")
            continue
        values_str = [str(v) for v in present if isinstance(v, str)]
        if not values_str:
            continue
        distinct = sorted(set(values_str))
        if 2 <= len(distinct) <= 10:
            counts = {v: values_str.count(v) for v in distinct}
            summary = ", ".join(f"{v}={counts[v]}" for v in sorted(counts))
            facts.append(f"{k} distribution: {summary}")

    return _truncate_facts(facts, max_facts)


def _summarize_dict(data: dict[str, Any], *, max_facts: int) -> list[str]:
    facts: list[str] = [f"Keys: {', '.join(sorted(data.keys())[:20])}"]
    # Build at most ``max_facts`` value facts — never one per key — so a huge
    # dict does not turn a bounded summary into an O(n) walk on the hot path.
    for k, v in islice(data.items(), max_facts):
        if isinstance(v, (int, float)):
            facts.append(f"{k}: {v}")
        elif isinstance(v, str):
            facts.append(f"{k}: {v[:80]}")
        elif isinstance(v, list):
            facts.append(f"{k}: list of {len(v)} items")
        elif isinstance(v, dict):
            facts.append(f"{k}: dict with keys [{', '.join(list(v.keys())[:5])}]")
        else:
            facts.append(f"{k}: {repr(v)[:80]}")
    return _truncate_facts(facts, max_facts, total=1 + len(data))


def _summarize_plain_list(data: list[Any], *, max_facts: int) -> list[str]:
    # Only repr() up to ``max_facts`` elements; the total count is already
    # surfaced by the "List of N items" header and threaded to the marker.
    facts = [f"List of {len(data)} items"]
    facts.extend(repr(item)[:100] for item in islice(data, max_facts))
    return _truncate_facts(facts, max_facts, total=1 + len(data))


def _summarize_string(data: str, *, max_facts: int) -> list[str]:
    truncated = data[:500]
    if len(data) > 500:
        truncated += f"… ({len(data)} chars total)"
    return [truncated][:max_facts]
