"""Tests for the context Firewall."""

from __future__ import annotations

import datetime

from agent_kernel import Firewall
from agent_kernel.firewall.budgets import Budgets
from agent_kernel.firewall.summarize import summarize
from agent_kernel.models import Handle, RawResult


def _handle() -> Handle:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return Handle(
        handle_id="h1",
        capability_id="cap.x",
        created_at=now,
        expires_at=now + datetime.timedelta(hours=1),
        total_rows=200,
    )


def _transform(
    data: object,
    response_mode: str = "summary",
    *,
    principal_roles: list[str] | None = None,
    constraints: dict[str, object] | None = None,
    budgets: Budgets | None = None,
) -> object:
    fw = Firewall(budgets=budgets)
    raw = RawResult(capability_id="cap.x", data=data)
    return fw.transform(
        raw,
        action_id="act-1",
        principal_id="u1",
        principal_roles=principal_roles or [],
        response_mode=response_mode,  # type: ignore[arg-type]
        constraints=constraints,
        handle=_handle(),
    )


# ── Summary mode ───────────────────────────────────────────────────────────────


def test_summary_list_of_dicts() -> None:
    rows = [{"id": i, "amount": float(i * 10)} for i in range(100)]
    frame = _transform(rows, "summary")
    assert frame.response_mode == "summary"  # type: ignore[union-attr]
    assert len(frame.facts) > 0  # type: ignore[union-attr]
    assert "Total rows: 100" in frame.facts  # type: ignore[union-attr]


def test_summary_dict() -> None:
    data = {"totals": {"USD": 1000.0}, "invoice_count": 200}
    frame = _transform(data, "summary")
    assert any("invoice_count" in f for f in frame.facts)  # type: ignore[union-attr]


def test_summary_string() -> None:
    frame = _transform("hello world", "summary")
    assert frame.response_mode == "summary"  # type: ignore[union-attr]


# ── Table mode ─────────────────────────────────────────────────────────────────


def test_table_row_cap() -> None:
    rows = [{"id": i} for i in range(200)]
    budgets = Budgets(max_rows=10)
    frame = _transform(rows, "table", budgets=budgets)
    assert len(frame.table_preview) <= 10  # type: ignore[union-attr]


def test_table_field_cap() -> None:
    rows = [{"f" + str(j): j for j in range(50)}]
    budgets = Budgets(max_fields=5)
    frame = _transform(rows, "table", budgets=budgets)
    assert all(len(r) <= 5 for r in frame.table_preview)  # type: ignore[union-attr]


def test_table_max_rows_from_constraints() -> None:
    rows = [{"id": i} for i in range(100)]
    frame = _transform(rows, "table", constraints={"max_rows": 3})
    assert len(frame.table_preview) <= 3  # type: ignore[union-attr]


# ── Handle-only mode ───────────────────────────────────────────────────────────


def test_handle_only() -> None:
    frame = _transform([1, 2, 3], "handle_only")
    assert frame.response_mode == "handle_only"  # type: ignore[union-attr]
    assert frame.handle is not None  # type: ignore[union-attr]
    assert frame.table_preview == []  # type: ignore[union-attr]
    assert frame.facts == []  # type: ignore[union-attr]


# ── Raw mode ───────────────────────────────────────────────────────────────────


def test_raw_mode_admin() -> None:
    data = {"secret": "data"}
    frame = _transform(data, "raw", principal_roles=["admin"])
    assert frame.response_mode == "raw"  # type: ignore[union-attr]
    assert frame.raw_data is not None  # type: ignore[union-attr]


def test_raw_mode_non_admin_falls_back_to_summary() -> None:
    data = {"secret": "data"}
    frame = _transform(data, "raw", principal_roles=["reader"])
    assert frame.response_mode == "summary"  # type: ignore[union-attr]
    assert any("raw mode requires admin" in w for w in frame.warnings)  # type: ignore[union-attr]


# ── Char budget ────────────────────────────────────────────────────────────────


def test_char_budget_limits_facts() -> None:
    big_string = "x" * 3000
    rows = [{"description": big_string} for _ in range(10)]
    budgets = Budgets(max_chars=100)
    frame = _transform(rows, "summary", budgets=budgets)
    total = sum(len(f) for f in frame.facts)  # type: ignore[union-attr]
    assert total <= 200  # allow some slack for the budget check


# ── PII redaction ──────────────────────────────────────────────────────────────


def test_pii_allowed_fields_redaction() -> None:
    rows = [{"id": 1, "email": "user@example.com", "amount": 100.0}]
    frame = _transform(
        rows,
        "table",
        constraints={"allowed_fields": ["id", "amount"]},
    )
    row = frame.table_preview[0]  # type: ignore[union-attr]
    assert "email" not in row
    assert "id" in row


def test_redaction_warnings() -> None:
    rows = [{"id": 1, "email": "test@example.com"}]
    frame = _transform(rows, "table", constraints={"allowed_fields": ["id"]})
    assert any("email" in w for w in frame.warnings)  # type: ignore[union-attr]


# ── max_depth ──────────────────────────────────────────────────────────────────


def test_max_depth_limiting() -> None:
    deep = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
    budgets = Budgets(max_depth=2)
    frame = _transform(deep, "summary", budgets=budgets)
    assert frame.response_mode == "summary"  # type: ignore[union-attr]


# ── Raw mode budget warning ────────────────────────────────────────────────────


def test_raw_mode_oversized_data_adds_warning() -> None:
    large_data = {"payload": "x" * 10_000}
    budgets = Budgets(max_chars=100)
    frame = _transform(large_data, "raw", principal_roles=["admin"], budgets=budgets)
    assert frame.response_mode == "raw"  # type: ignore[union-attr]
    assert any("exceeds budget" in w for w in frame.warnings)  # type: ignore[union-attr]


# ── Table mode with non-list data ──────────────────────────────────────────────


def test_table_mode_single_dict() -> None:
    frame = _transform({"a": 1, "b": 2}, "table")
    assert frame.response_mode == "table"  # type: ignore[union-attr]
    assert len(frame.table_preview) == 1  # type: ignore[union-attr]
    assert frame.table_preview[0]["a"] == 1  # type: ignore[union-attr]


def test_table_mode_non_dict_rows() -> None:
    frame = _transform([1, 2, 3], "table")
    assert frame.response_mode == "table"  # type: ignore[union-attr]
    assert frame.table_preview[0] == {"value": 1}  # type: ignore[union-attr]


def test_table_mode_scalar_data() -> None:
    frame = _transform(42, "table")
    assert frame.response_mode == "table"  # type: ignore[union-attr]
    assert frame.table_preview == [{"value": 42}]  # type: ignore[union-attr]


# ── _cap_facts via public interface ────────────────────────────────────────────


def test_summary_cap_facts_stops_at_budget() -> None:
    # "Keys: key1, key2" (16 chars) fits in max_chars=20; the next fact (46+ chars)
    # pushes the running total over budget, triggering the break in _cap_facts.
    data = {"key1": "v" * 40, "key2": "v" * 40}
    budgets = Budgets(max_chars=20)
    frame = _transform(data, "summary", budgets=budgets)
    assert frame.response_mode == "summary"  # type: ignore[union-attr]
    assert len(frame.facts) == 1  # type: ignore[union-attr]
    assert "Keys" in frame.facts[0]  # type: ignore[union-attr]


def test_cap_facts_all_fit() -> None:
    # Both short facts fit well within a generous budget — no break triggered.
    data = {"a": 1, "b": 2}
    budgets = Budgets(max_chars=10_000)
    frame = _transform(data, "summary", budgets=budgets)
    assert frame.response_mode == "summary"  # type: ignore[union-attr]
    assert len(frame.facts) >= 2  # type: ignore[union-attr]


# ── summarize() edge cases ─────────────────────────────────────────────────────


def test_summarize_plain_list() -> None:
    facts = summarize([1, 2, 3, "hello"])
    assert facts[0] == "List of 4 items"
    assert "1" in facts[1]


def test_summarize_other_type_int() -> None:
    facts = summarize(42)
    assert facts == ["42"]


def test_summarize_other_type_none() -> None:
    facts = summarize(None)
    assert facts == ["None"]


def test_summarize_string_truncation() -> None:
    long_str = "a" * 600
    facts = summarize(long_str)
    assert len(facts) == 1
    assert "600 chars total" in facts[0]
    assert facts[0].startswith("a" * 500)


def test_summarize_list_of_dicts_numeric_max_facts() -> None:
    rows = [{"n1": i, "n2": i * 2, "n3": i * 3} for i in range(5)]
    # max_facts=3: "Total rows" + "Top keys" = 2, then 1 numeric fact hits limit
    facts = summarize(rows, max_facts=3)
    assert len(facts) <= 3


def test_summarize_list_of_dicts_categorical_distribution() -> None:
    rows = [{"status": s} for s in ["open", "closed", "open", "pending", "closed"]]
    facts = summarize(rows)
    assert any("distribution" in f for f in facts)


def test_summarize_list_of_dicts_no_string_values_in_field() -> None:
    # List values are not strings and not numeric — categorical loop skips them
    rows = [{"items": [1, 2]}, {"items": [3, 4]}, {"items": [5]}]
    facts = summarize(rows)
    assert any("Total rows" in f for f in facts)


def test_summarize_list_of_dicts_categorical_max_facts() -> None:
    rows = [{"status": s, "kind": k} for s, k in [("a", "x"), ("b", "y"), ("a", "z"), ("b", "x")]]
    # max_facts=3: "Total rows" + "Top keys" + 1 categorical fact, then break
    facts = summarize(rows, max_facts=3)
    assert len(facts) <= 3


def test_summarize_dict_list_value() -> None:
    data = {"items": [1, 2, 3], "count": 3}
    facts = summarize(data)
    assert any("list of 3 items" in f for f in facts)


def test_summarize_dict_other_value_type() -> None:
    # Tuple is not int/float/str/list/dict — falls through to repr()
    data = {"pair": (1, 2), "count": 1}
    facts = summarize(data)
    assert any("(1, 2)" in f for f in facts)


def test_summarize_dict_max_facts() -> None:
    data = {"a": 1, "b": 2, "c": 3}
    facts = summarize(data, max_facts=2)
    assert len(facts) <= 2
