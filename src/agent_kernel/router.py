"""Router: maps a capability to an ordered list of drivers to try."""

from __future__ import annotations

from typing import Protocol

from .models import RoutePlan


class Router(Protocol):
    """Interface for routing a capability invocation to drivers."""

    def route(self, capability_id: str) -> RoutePlan:
        """Return an ordered list of driver IDs to try for *capability_id*.

        Args:
            capability_id: The capability being invoked.

        Returns:
            A :class:`RoutePlan` with an ordered ``driver_ids`` list.
        """
        ...


class StaticRouter:
    """A router backed by a static mapping of capability → driver IDs.

    Capabilities not in the explicit map fall back to a configurable default
    driver list (e.g. ``["memory"]``).
    """

    def __init__(
        self,
        routes: dict[str, list[str]] | None = None,
        fallback: list[str] | None = None,
    ) -> None:
        """Initialise the router.

        Args:
            routes: Explicit ``{capability_id: [driver_id, ...]}`` mapping.
            fallback: Driver IDs to use when no explicit route is found.
        """
        self._routes: dict[str, list[str]] = routes or {}
        self._fallback: list[str] = fallback or ["memory"]

    def add_route(self, capability_id: str, driver_ids: list[str]) -> None:
        """Add or replace a route.

        Args:
            capability_id: The capability to route.
            driver_ids: Ordered list of driver IDs.
        """
        self._routes[capability_id] = driver_ids

    def route(self, capability_id: str) -> RoutePlan:
        """Return a :class:`RoutePlan` for *capability_id*.

        Args:
            capability_id: The capability being invoked.

        Returns:
            The explicit route if defined, otherwise the fallback route.
        """
        driver_ids = self._routes.get(capability_id, self._fallback)
        return RoutePlan(capability_id=capability_id, driver_ids=list(driver_ids))
