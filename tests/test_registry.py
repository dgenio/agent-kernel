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


# ── Namespace operations (#45) ────────────────────────────────────────────────


def test_list_namespaces_from_registered_capabilities() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.invoices.list"))
    reg.register(_make_cap("billing.invoices.create"))
    reg.register(_make_cap("crm.contacts.search"))
    reg.register(_make_cap("flat_id"))
    assert reg.list_namespaces() == ["billing", "crm", "flat_id"]


def test_list_namespace_returns_capabilities_under_prefix() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.invoices.list"))
    reg.register(_make_cap("billing.invoices.create"))
    reg.register(_make_cap("billing.payments.refund"))
    reg.register(_make_cap("crm.contacts.search"))

    billing = [c.capability_id for c in reg.list_namespace("billing")]
    assert sorted(billing) == [
        "billing.invoices.create",
        "billing.invoices.list",
        "billing.payments.refund",
    ]

    invoices = [c.capability_id for c in reg.list_namespace("billing.invoices")]
    assert sorted(invoices) == [
        "billing.invoices.create",
        "billing.invoices.list",
    ]


def test_list_namespace_exact_match_is_included() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing"))
    reg.register(_make_cap("billing.invoices.list"))
    ids = [c.capability_id for c in reg.list_namespace("billing")]
    assert "billing" in ids
    assert "billing.invoices.list" in ids


def test_list_namespace_unknown_prefix_raises() -> None:
    from agent_kernel import NamespaceNotFound

    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.invoices.list"))
    with pytest.raises(NamespaceNotFound, match="no registered capabilities"):
        reg.list_namespace("never.declared")


def test_register_namespace_duplicate_raises() -> None:
    reg = CapabilityRegistry()
    reg.register_namespace("billing", description="Billing tools")
    with pytest.raises(CapabilityAlreadyRegistered, match="already declared"):
        reg.register_namespace("billing")


def test_deferred_loader_called_exactly_once_on_first_access() -> None:
    call_count = {"n": 0}

    def loader() -> list[Capability]:
        call_count["n"] += 1
        return [_make_cap("ondemand.list"), _make_cap("ondemand.create")]

    reg = CapabilityRegistry()
    reg.register_namespace("ondemand", description="Lazy loaded", loader=loader)

    # First access triggers the loader.
    caps = reg.list_namespace("ondemand")
    assert {c.capability_id for c in caps} == {"ondemand.list", "ondemand.create"}
    assert call_count["n"] == 1

    # Second access does not re-invoke.
    reg.list_namespace("ondemand")
    assert call_count["n"] == 1


def test_deferred_loader_triggers_on_get() -> None:
    def loader() -> list[Capability]:
        return [_make_cap("lazy.thing")]

    reg = CapabilityRegistry()
    reg.register_namespace("lazy", loader=loader)
    cap = reg.get("lazy.thing")
    assert cap.capability_id == "lazy.thing"


def test_deferred_loader_triggers_on_search_overlap() -> None:
    call_count = {"n": 0}

    def loader() -> list[Capability]:
        call_count["n"] += 1
        return [_make_cap("billing.weekly_report", description="weekly revenue report")]

    reg = CapabilityRegistry()
    reg.register_namespace("billing", loader=loader)
    results = reg.search("weekly billing")
    ids = [r.capability_id for r in results]
    assert "billing.weekly_report" in ids
    assert call_count["n"] == 1


def test_list_namespace_loads_ancestor_loader() -> None:
    """list_namespace on a child prefix triggers an ancestor's deferred loader."""

    def loader() -> list[Capability]:
        return [_make_cap("billing.invoices.list"), _make_cap("billing.invoices.create")]

    reg = CapabilityRegistry()
    reg.register_namespace("billing", loader=loader)
    caps = reg.list_namespace("billing.invoices")
    assert {c.capability_id for c in caps} == {
        "billing.invoices.list",
        "billing.invoices.create",
    }


def test_get_loads_intermediate_namespace_loader() -> None:
    """get() triggers a loader declared on a nested (intermediate) prefix."""

    def loader() -> list[Capability]:
        return [_make_cap("billing.invoices.list")]

    reg = CapabilityRegistry()
    reg.register_namespace("billing.invoices", loader=loader)
    assert reg.get("billing.invoices.list").capability_id == "billing.invoices.list"


def test_get_loads_deepest_declared_namespace_only() -> None:
    """When several ancestors are declared, only the deepest loader runs."""
    loaded: list[str] = []

    def shallow() -> list[Capability]:
        loaded.append("billing")
        return []

    def deep() -> list[Capability]:
        loaded.append("billing.invoices")
        return [_make_cap("billing.invoices.list")]

    reg = CapabilityRegistry()
    reg.register_namespace("billing", loader=shallow)
    reg.register_namespace("billing.invoices", loader=deep)
    assert reg.get("billing.invoices.list").capability_id == "billing.invoices.list"
    assert loaded == ["billing.invoices"]


def test_namespace_loader_out_of_namespace_capability_raises() -> None:
    """A loader returning a capability outside its namespace is a contract error."""
    from agent_kernel import FederationError

    def loader() -> list[Capability]:
        return [_make_cap("billing.invoices.list"), _make_cap("crm.contacts.list")]

    reg = CapabilityRegistry()
    reg.register_namespace("billing", loader=loader)
    with pytest.raises(FederationError, match="does not live under the namespace"):
        reg.list_namespace("billing")
    # The whole batch is rejected — nothing is registered on a contract violation.
    assert reg.list_all() == []


def test_search_negative_offset_is_clamped() -> None:
    reg = CapabilityRegistry()
    for i in range(5):
        reg.register(_make_cap(f"billing.invoice{i:02d}", tags=["invoice"]))
    baseline = reg.search("invoice", offset=0)
    assert reg.search("invoice", offset=-3) == baseline


def test_search_negative_max_results_returns_empty() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.list", tags=["invoice"]))
    assert reg.search("invoice", max_results=-1) == []


# ── Search scoring & pagination (#45) ─────────────────────────────────────────


def test_search_id_match_ranks_above_description_only() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("invoices.list", description="unrelated text"))
    reg.register(
        _make_cap(
            "ledger.report",
            description="invoices summary",
        )
    )
    results = reg.search("invoices")
    assert [r.capability_id for r in results][:2] == ["invoices.list", "ledger.report"]


def test_search_pagination_offset() -> None:
    reg = CapabilityRegistry()
    for i in range(15):
        reg.register(_make_cap(f"billing.invoice{i:02d}", tags=["invoice"]))
    page1 = reg.search("invoice", max_results=5, offset=0)
    page2 = reg.search("invoice", max_results=5, offset=5)
    page3 = reg.search("invoice", max_results=5, offset=10)
    assert len(page1) == 5
    assert len(page2) == 5
    assert len(page3) == 5
    ids = {r.capability_id for r in page1 + page2 + page3}
    assert len(ids) == 15


def test_search_pagination_offset_does_not_overlap() -> None:
    reg = CapabilityRegistry()
    for i in range(10):
        reg.register(_make_cap(f"billing.invoice{i:02d}", tags=["invoice"]))
    page1 = {r.capability_id for r in reg.search("invoice", max_results=4, offset=0)}
    page2 = {r.capability_id for r in reg.search("invoice", max_results=4, offset=4)}
    assert page1.isdisjoint(page2)


def test_search_stop_words_are_stripped() -> None:
    reg = CapabilityRegistry()
    reg.register(_make_cap("billing.list_invoices"))
    # "to" / "the" / "please" must not contribute matches.
    results = reg.search("the to please")
    assert results == []


def test_search_tags_outrank_description() -> None:
    reg = CapabilityRegistry()
    reg.register(
        _make_cap(
            "alpha.report",
            description="quarterly revenue summary",
            tags=["analytics"],
        )
    )
    reg.register(
        _make_cap(
            "beta.report",
            description="alpha analytics description",
            tags=["unrelated"],
        )
    )
    results = reg.search("analytics")
    assert [r.capability_id for r in results][0] == "alpha.report"


def test_search_scales_to_500_capabilities() -> None:
    """Search over 500 capabilities stays correct and deterministic."""
    reg = CapabilityRegistry()
    for i in range(500):
        ns = "billing" if i % 2 == 0 else "crm"
        reg.register(
            _make_cap(
                f"{ns}.thing{i:04d}",
                description=f"deterministic stuff for record {i}",
                tags=[ns, "thing"],
            )
        )
    results = reg.search("billing thing", max_results=10)
    ids = [r.capability_id for r in results]
    assert len(ids) == 10
    # Deterministic ordering: an identical query returns identical results.
    assert [r.capability_id for r in reg.search("billing thing", max_results=10)] == ids
    # The 'billing' token outweighs 'crm', so all top hits are billing IDs.
    assert all(i.startswith("billing.") for i in ids)
