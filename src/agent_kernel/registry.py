"""Capability registry: register, lookup, and keyword-based matching."""

from __future__ import annotations

import re

from .errors import CapabilityAlreadyRegistered, CapabilityNotFound
from .models import Capability, CapabilityRequest


class CapabilityRegistry:
    """Stores and retrieves :class:`Capability` objects.

    Capabilities are registered by their ``capability_id`` and can be looked
    up directly or discovered via keyword search against the goal description.
    """

    def __init__(self) -> None:
        self._store: dict[str, Capability] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, capability: Capability) -> None:
        """Register a capability.

        Args:
            capability: The :class:`Capability` to register.

        Raises:
            CapabilityAlreadyRegistered: If a capability with the same ID is already registered.
        """
        if capability.capability_id in self._store:
            raise CapabilityAlreadyRegistered(
                f"Capability '{capability.capability_id}' is already registered. "
                "Use a unique capability_id."
            )
        self._store[capability.capability_id] = capability

    def register_many(self, capabilities: list[Capability]) -> None:
        """Register multiple capabilities at once.

        Args:
            capabilities: List of :class:`Capability` objects to register.
        """
        for cap in capabilities:
            self.register(cap)

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, capability_id: str) -> Capability:
        """Retrieve a capability by its ID.

        Args:
            capability_id: The capability's stable identifier.

        Returns:
            The matching :class:`Capability`.

        Raises:
            CapabilityNotFound: If no capability with that ID exists.
        """
        try:
            return self._store[capability_id]
        except KeyError:
            raise CapabilityNotFound(
                f"No capability registered with id='{capability_id}'. "
                "Check the capability_id or register it first."
            ) from None

    def list_all(self) -> list[Capability]:
        """Return all registered capabilities in registration order."""
        return list(self._store.values())

    # ── Keyword matching ──────────────────────────────────────────────────────

    def search(self, goal: str, *, max_results: int = 10) -> list[CapabilityRequest]:
        """Search for capabilities matching a goal string.

        Splits *goal* into tokens and scores capabilities by how many tokens
        appear in their ``capability_id``, ``name``, ``description``, or
        ``tags``. Returns the top results as :class:`CapabilityRequest` objects.

        Args:
            goal: Free-text description of the user's intent.
            max_results: Maximum number of results to return.

        Returns:
            Ordered list (highest score first) of :class:`CapabilityRequest`.
        """
        tokens = self._tokenize(goal)
        if not tokens:
            return []

        scored: list[tuple[int, Capability]] = []
        for cap in self._store.values():
            score = self._score(cap, tokens)
            if score > 0:
                scored.append((score, cap))

        scored.sort(key=lambda x: (-x[0], x[1].capability_id))
        return [
            CapabilityRequest(capability_id=cap.capability_id, goal=goal)
            for _, cap in scored[:max_results]
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Split text into lower-case word tokens."""
        return re.findall(r"[a-z0-9]+", text.lower())

    @staticmethod
    def _score(cap: Capability, tokens: list[str]) -> int:
        """Return a match score for a capability against query tokens."""
        corpus = " ".join(
            [
                cap.capability_id,
                cap.name,
                cap.description,
            ]
            + cap.tags
        ).lower()
        return sum(1 for t in tokens if t in corpus)
