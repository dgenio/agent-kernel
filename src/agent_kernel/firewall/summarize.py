"""Deterministic summarization heuristics for the context firewall.

No LLM is used — summaries are produced by structural analysis of the data.
"""

from __future__ import annotations

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

    # Numeric stats
    numeric_keys = [
        k for k in top_keys if all(isinstance(r.get(k), (int, float)) for r in rows if k in r)
    ]
    for k in numeric_keys[:5]:
        values = [float(r[k]) for r in rows if k in r]
        if values:
            facts.append(
                f"{k}: min={min(values):.2f}, max={max(values):.2f}, "
                f"avg={sum(values) / len(values):.2f}"
            )
        if len(facts) >= max_facts:
            break

    # Status / categorical counts (string fields with few distinct values)
    for k in top_keys[:5]:
        if k in numeric_keys:
            continue
        values_str = [str(r[k]) for r in rows if k in r and isinstance(r[k], str)]
        if not values_str:
            continue
        distinct = sorted(set(values_str))
        if 2 <= len(distinct) <= 10:
            counts = {v: values_str.count(v) for v in distinct}
            summary = ", ".join(f"{v}={counts[v]}" for v in sorted(counts))
            facts.append(f"{k} distribution: {summary}")
        if len(facts) >= max_facts:
            break

    return facts[:max_facts]


def _summarize_dict(data: dict[str, Any], *, max_facts: int) -> list[str]:
    facts: list[str] = [f"Keys: {', '.join(sorted(data.keys())[:20])}"]
    for k, v in list(data.items())[: max_facts - 1]:
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
        if len(facts) >= max_facts:
            break
    return facts[:max_facts]


def _summarize_plain_list(data: list[Any], *, max_facts: int) -> list[str]:
    facts = [f"List of {len(data)} items"]
    for item in data[: max_facts - 1]:
        facts.append(repr(item)[:100])
    return facts[:max_facts]


def _summarize_string(data: str, *, max_facts: int) -> list[str]:
    truncated = data[:500]
    if len(data) > 500:
        truncated += f"… ({len(data)} chars total)"
    return [truncated][:max_facts]
