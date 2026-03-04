"""Tests for StaticRouter."""

from __future__ import annotations

from agent_kernel import StaticRouter


def test_explicit_route() -> None:
    router = StaticRouter(routes={"cap.x": ["http", "memory"]})
    plan = router.route("cap.x")
    assert plan.driver_ids == ["http", "memory"]
    assert plan.capability_id == "cap.x"


def test_fallback_route() -> None:
    router = StaticRouter(routes={}, fallback=["memory"])
    plan = router.route("cap.unknown")
    assert plan.driver_ids == ["memory"]


def test_default_fallback() -> None:
    router = StaticRouter()
    plan = router.route("anything")
    assert "memory" in plan.driver_ids


def test_add_route() -> None:
    router = StaticRouter()
    router.add_route("cap.new", ["http"])
    plan = router.route("cap.new")
    assert plan.driver_ids == ["http"]


def test_route_returns_copy() -> None:
    """Mutating the returned driver_ids should not affect the router."""
    router = StaticRouter(routes={"cap.x": ["memory"]})
    plan = router.route("cap.x")
    plan.driver_ids.append("corrupted")
    assert router.route("cap.x").driver_ids == ["memory"]
