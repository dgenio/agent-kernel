"""Tests for the context Firewall."""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from weaver_kernel import (
    BudgetConfigError,
    BudgetExhausted,
    BudgetManager,
    Firewall,
    default_token_counter,
)
from weaver_kernel.firewall.budgets import Budgets
from weaver_kernel.firewall.summarize import summarize
from weaver_kernel.models import Handle, RawResult


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
    assert frame.raw_data == large_data  # type: ignore[union-attr]


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


# ── summarize() bool handling + truncation marker (#174) ────────────────────────


def test_summarize_bool_column_is_not_averaged() -> None:
    rows = [{"active": True}, {"active": True}, {"active": False}]
    facts = summarize(rows)
    # A bool column must never be reported as a numeric mean/min/max.
    assert not any("avg=" in f for f in facts)
    assert any(f == "active: True=2, False=1" for f in facts)


def test_summarize_numeric_column_still_averaged() -> None:
    rows = [{"score": 10}, {"score": 20}, {"score": 30}]
    facts = summarize(rows)
    assert any(f == "score: min=10.00, max=30.00, avg=20.00" for f in facts)


def test_summarize_truncation_marker_when_facts_omitted() -> None:
    rows = [{"a": i, "b": i, "c": i, "d": i, "e": i} for i in range(5)]
    facts = summarize(rows, max_facts=3)
    assert len(facts) == 3
    assert "more facts omitted" in facts[-1]


def test_summarize_no_marker_when_all_facts_fit() -> None:
    rows = [{"score": i} for i in range(3)]
    facts = summarize(rows, max_facts=20)
    assert not any("omitted" in f for f in facts)


def test_summarize_exactly_max_facts_has_no_false_marker() -> None:
    # "Keys" + "a: 1" + "b: 2" is exactly 3 facts; no truncation should occur.
    facts = summarize({"a": 1, "b": 2}, max_facts=3)
    assert facts == ["Keys: a, b", "a: 1", "b: 2"]


def test_summarize_plain_list_marks_omitted_items() -> None:
    facts = summarize(list(range(10)), max_facts=4)
    assert facts[0] == "List of 10 items"
    assert "more facts omitted" in facts[-1]


# ── Token counting ─────────────────────────────────────────────────────────────


def test_default_token_counter_none_is_zero() -> None:
    assert default_token_counter(None) == 0


def test_default_token_counter_str_chars_over_four() -> None:
    # JSON-encoded form is "hello world" with quotes → 13 chars → 3 tokens.
    assert default_token_counter("hello world") == 3


def test_default_token_counter_dict_uses_json_chars() -> None:
    value: dict[str, Any] = {"id": 1, "name": "alice"}
    # len('{"id": 1, "name": "alice"}') == 26 → 26 // 4 == 6.
    assert default_token_counter(value) == 6


def test_default_token_counter_non_json_falls_back_to_str() -> None:
    class NotSerialisable:
        def __repr__(self) -> str:
            return "X" * 100

    # The repr is 100 chars; default=str → 100 chars → 25 tokens.
    # Wrapping in JSON adds two quotes → 102 chars → 25 tokens.
    assert default_token_counter(NotSerialisable()) == 25


# ── BudgetManager: construction validation ─────────────────────────────────────


def test_budget_manager_rejects_non_positive_total() -> None:
    with pytest.raises(BudgetConfigError, match="total_budget must be positive"):
        BudgetManager(total_budget=0)
    with pytest.raises(BudgetConfigError, match="total_budget must be positive"):
        BudgetManager(total_budget=-1)


def test_budget_manager_rejects_non_positive_default_request() -> None:
    with pytest.raises(BudgetConfigError, match="default_request must be positive"):
        BudgetManager(total_budget=100, default_request=0)


# ── BudgetManager: allocation / recording ─────────────────────────────────────


@pytest.mark.asyncio
async def test_allocate_grants_full_when_under_budget() -> None:
    bm = BudgetManager(total_budget=1000)
    granted = await bm.allocate(200)
    assert granted == 200
    assert bm.remaining == 800
    assert bm.used == 0  # reservation, not commit


@pytest.mark.asyncio
async def test_allocate_caps_at_remaining() -> None:
    bm = BudgetManager(total_budget=1000)
    await bm.allocate(700)  # reserve 700
    granted = await bm.allocate(500)
    # Only 300 is free after the first reservation.
    assert granted == 300
    assert bm.remaining == 0


@pytest.mark.asyncio
async def test_allocate_uses_default_request_when_none() -> None:
    bm = BudgetManager(total_budget=1000, default_request=250)
    granted = await bm.allocate()
    assert granted == 250


@pytest.mark.asyncio
async def test_allocate_rejects_negative_request() -> None:
    bm = BudgetManager(total_budget=1000)
    with pytest.raises(BudgetConfigError, match="non-negative"):
        await bm.allocate(-10)


@pytest.mark.asyncio
async def test_allocate_raises_budget_exhausted_when_empty() -> None:
    bm = BudgetManager(total_budget=100)
    await bm.allocate(100)
    await bm.record_usage(100, reserved=100)
    with pytest.raises(BudgetExhausted, match="Session budget exhausted"):
        await bm.allocate(10)


@pytest.mark.asyncio
async def test_record_usage_reconciles_under_reservation() -> None:
    bm = BudgetManager(total_budget=1000)
    reserved = await bm.allocate(400)
    await bm.record_usage(150, reserved=reserved)
    # Released the 400 reservation, committed 150 → remaining = 850.
    assert bm.used == 150
    assert bm.remaining == 850


@pytest.mark.asyncio
async def test_record_usage_caps_used_at_total() -> None:
    # Defensive: actual > total should never push used above total.
    bm = BudgetManager(total_budget=100)
    await bm.record_usage(999)
    assert bm.used == 100
    assert bm.remaining == 0


@pytest.mark.asyncio
async def test_record_usage_rejects_negative() -> None:
    bm = BudgetManager(total_budget=1000)
    with pytest.raises(BudgetConfigError, match="non-negative"):
        await bm.record_usage(-1)


@pytest.mark.asyncio
async def test_record_usage_rejects_negative_reserved() -> None:
    bm = BudgetManager(total_budget=1000)
    with pytest.raises(BudgetConfigError, match="reserved must be non-negative"):
        await bm.record_usage(0, reserved=-5)


@pytest.mark.asyncio
async def test_release_returns_reservation_to_pool() -> None:
    bm = BudgetManager(total_budget=1000)
    reserved = await bm.allocate(400)
    await bm.release(reserved)
    assert bm.remaining == 1000
    assert bm.used == 0


@pytest.mark.asyncio
async def test_release_rejects_negative() -> None:
    bm = BudgetManager(total_budget=1000)
    with pytest.raises(BudgetConfigError, match="reserved must be non-negative"):
        await bm.release(-1)


def test_budget_config_error_is_weaver_kernel_error() -> None:
    """``BudgetConfigError`` is part of the public exception hierarchy."""
    from weaver_kernel import AgentKernelError

    assert issubclass(BudgetConfigError, AgentKernelError)


# ── BudgetManager: properties ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_usage_fraction_progresses() -> None:
    bm = BudgetManager(total_budget=200)
    assert bm.usage_fraction == 0.0
    await bm.record_usage(100)
    assert bm.usage_fraction == 0.5
    await bm.record_usage(100)
    assert bm.usage_fraction == 1.0


def test_total_budget_reflects_constructor() -> None:
    bm = BudgetManager(total_budget=12345)
    assert bm.total_budget == 12345


# ── BudgetManager: custom counter ──────────────────────────────────────────────


def test_custom_token_counter_is_used() -> None:
    calls: list[Any] = []

    def fake_counter(value: Any) -> int:
        calls.append(value)
        return 42

    bm = BudgetManager(total_budget=1000, token_counter=fake_counter)
    assert bm.count_tokens({"x": 1}) == 42
    assert calls == [{"x": 1}]


# ── BudgetManager: suggested_mode escalation table ─────────────────────────────


@pytest.mark.asyncio
async def test_suggested_mode_above_fifty_percent_keeps_requested() -> None:
    bm = BudgetManager(total_budget=1000)
    # 0% used → 100% remaining
    assert bm.suggested_mode("raw") == "raw"
    assert bm.suggested_mode("table") == "table"
    assert bm.suggested_mode("summary") == "summary"


@pytest.mark.asyncio
async def test_suggested_mode_between_twenty_and_fifty_downgrades_raw_only() -> None:
    bm = BudgetManager(total_budget=1000)
    # Consume 600 → remaining 400 → 40%
    await bm.record_usage(600)
    assert bm.suggested_mode("raw") == "table"
    assert bm.suggested_mode("table") == "table"
    assert bm.suggested_mode("summary") == "summary"
    assert bm.suggested_mode("handle_only") == "handle_only"


@pytest.mark.asyncio
async def test_suggested_mode_between_five_and_twenty_floors_at_summary() -> None:
    bm = BudgetManager(total_budget=1000)
    # Consume 850 → remaining 150 → 15%
    await bm.record_usage(850)
    assert bm.suggested_mode("raw") == "summary"
    assert bm.suggested_mode("table") == "summary"
    assert bm.suggested_mode("summary") == "summary"
    assert bm.suggested_mode("handle_only") == "handle_only"


@pytest.mark.asyncio
async def test_suggested_mode_under_five_percent_forces_handle_only() -> None:
    bm = BudgetManager(total_budget=1000)
    # Consume 980 → remaining 20 → 2%
    await bm.record_usage(980)
    assert bm.suggested_mode("raw") == "handle_only"
    assert bm.suggested_mode("table") == "handle_only"
    assert bm.suggested_mode("summary") == "handle_only"
    assert bm.suggested_mode("handle_only") == "handle_only"


@pytest.mark.asyncio
async def test_suggested_mode_boundary_exactly_fifty_percent_downgrades() -> None:
    # The boundary is strict-less-than, so remaining == 50% sits in the
    # 20–50% bucket and downgrades raw.
    bm = BudgetManager(total_budget=1000)
    await bm.record_usage(500)
    assert bm.suggested_mode("raw") == "table"


@pytest.mark.asyncio
async def test_suggested_mode_boundary_exactly_twenty_percent_floors_summary() -> None:
    bm = BudgetManager(total_budget=1000)
    await bm.record_usage(800)
    assert bm.suggested_mode("raw") == "summary"
    assert bm.suggested_mode("table") == "summary"


@pytest.mark.asyncio
async def test_suggested_mode_boundary_exactly_five_percent_is_summary_not_handle_only() -> None:
    # 5% exactly sits in the 5–20% summary bucket because the handle_only
    # guard is strictly-less-than: (0.05 < 0.05) is False.  A future change
    # from `< 0.05` to `<= 0.05` would silently misplace this boundary.
    bm = BudgetManager(total_budget=1000)
    await bm.record_usage(950)  # 5% remaining
    assert bm.suggested_mode("raw") == "summary"
    assert bm.suggested_mode("table") == "summary"
    assert bm.suggested_mode("summary") == "summary"
    assert bm.suggested_mode("handle_only") == "handle_only"  # never relaxes
