"""Tests for CapabilityRegistry."""

from __future__ import annotations

import pytest

from agent_kernel import (
    Capability,
    CapabilityAlreadyRegistered,
    CapabilityNotFound,
    CapabilityRegistry,
    SafetyClass,
)


def _make_cap(cap_id: str, **kwargs: object) -> Capability:
    defaults: dict[str, object] = {
        "name": cap_id.replace(".", " ").title(),
        "description": f"Description for {cap_id}",
        "safety_class": SafetyClass.READ,
    }
    defaults.update(kwargs)
    return Capability(capability_id=cap_id, **defaults)  # type: ignore[arg-type]


def test_register_and_get() -> None:
    reg = CapabilityRegistry()
    cap = _make_cap("test.cap")
    reg.register(cap)
    assert reg.get("test.cap") is cap


def test_register_duplicate_raises() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("test.dup"))
    with pytest.raises(CapabilityAlreadyRegistered, match="already registered"):
        reg.register(_make_cap("test.dup"))


def test_get_unknown_raises() -> None:
    reg = CapabilityRegistry()
    with pytest.raises(CapabilityNotFound):
        reg.get("does.not.exist")


def test_register_many() -> None:
    reg = CapabilityRegistry()
    caps = [_make_cap(f"cap.{i}") for i in range(5)]
    reg.register_many(caps)
    assert len(reg.list_all()) == 5


def test_list_all_order() -> None:
    reg = CapabilityRegistry()
    for i in range(3):
        reg.register(_make_cap(f"cap.{i}"))
    ids = [c.capability_id for c in reg.list_all()]
    assert ids == ["cap.0", "cap.1", "cap.2"]


def test_search_basic(registry: CapabilityRegistry) -> None:
    results = registry.search("list invoices")
    assert len(results) > 0
    ids = [r.capability_id for r in results]
    assert "billing.list_invoices" in ids


def test_search_returns_capabilityrequest(registry: CapabilityRegistry) -> None:
    from agent_kernel.models import CapabilityRequest

    results = registry.search("billing invoice")
    assert all(isinstance(r, CapabilityRequest) for r in results)


def test_search_empty_goal(registry: CapabilityRegistry) -> None:
    results = registry.search("")
    assert results == []


def test_search_no_matches(registry: CapabilityRegistry) -> None:
    results = registry.search("zzz completely unrelated xyz")
    assert results == []


def test_search_max_results() -> None:
    reg = CapabilityRegistry()
    for i in range(20):
        reg.register(_make_cap(f"search.cap{i}", description=f"billing invoice item {i}"))
    results = reg.search("billing invoice", max_results=5)
    assert len(results) <= 5


def test_search_keyword_in_tags() -> None:
    reg = CapabilityRegistry()
    reg.register(
        Capability(
            capability_id="tag.test",
            name="Tag Test",
            description="Unrelated description",
            safety_class=SafetyClass.READ,
            tags=["uniquetag123"],
        )
    )
    results = reg.search("uniquetag123")
    assert len(results) == 1
    assert results[0].capability_id == "tag.test"


def test_search_goal_preserved(registry: CapabilityRegistry) -> None:
    goal = "list all billing invoices please"
    results = registry.search(goal)
    assert all(r.goal == goal for r in results)
