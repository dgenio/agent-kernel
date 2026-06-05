"""Capability registry: register, lookup, namespaced discovery, and ranked search.

Supports dot-notation namespaces (``"billing.invoices.list"``) and deferred
namespace loaders for large tool ecosystems; ranked search is delegated to
:mod:`weaver_kernel.search_index`. Flat capability IDs continue to work — they
live in a single-segment namespace named after themselves.
"""

from __future__ import annotations

from collections.abc import Callable

from .errors import (
    CapabilityAlreadyRegistered,
    CapabilityNotFound,
    FederationError,
    NamespaceNotFound,
)
from .models import Capability, CapabilityRequest, NamespaceMetadata
from .search_index import SearchIndex, tokenize


class CapabilityRegistry:
    """Stores and retrieves :class:`Capability` objects.

    Capabilities are registered by their dot-notation ``capability_id``
    (e.g. ``"billing.invoices.list"``) and can be:

    - looked up directly via :meth:`get`,
    - enumerated globally via :meth:`list_all`,
    - enumerated per namespace via :meth:`list_namespaces` /
      :meth:`list_namespace`,
    - discovered via ranked text search (:meth:`search`).

    Flat IDs without a ``"."`` continue to work — they live in a single-
    segment namespace named after themselves.
    """

    def __init__(self) -> None:
        self._store: dict[str, Capability] = {}
        self._namespaces: dict[str, NamespaceMetadata] = {}
        # BM25 statistics live in the search index, refreshed lazily on change.
        self._index = SearchIndex()

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
        self._index.mark_dirty()

    def register_many(self, capabilities: list[Capability]) -> None:
        """Register multiple capabilities at once.

        Args:
            capabilities: List of :class:`Capability` objects to register.
        """
        for cap in capabilities:
            self.register(cap)

    def register_namespace(
        self,
        prefix: str,
        *,
        description: str = "",
        loader: Callable[[], list[Capability]] | None = None,
    ) -> None:
        """Declare a namespace, optionally with a deferred loader.

        The loader (if given) is invoked exactly once, the first time the
        namespace is searched, listed, or otherwise traversed. This lets a
        host process advertise hundreds of namespaces without paying the
        registration cost up front.

        Args:
            prefix: Dot-notation namespace prefix (e.g. ``"billing"``).
            description: Optional human-readable description.
            loader: Optional zero-arg callable returning capabilities to
                register on first access. Every returned capability's
                ``capability_id`` must start with ``prefix`` (followed by ``.``)
                or equal ``prefix`` exactly.

        Raises:
            CapabilityAlreadyRegistered: If the namespace is already declared.
        """
        if prefix in self._namespaces:
            raise CapabilityAlreadyRegistered(
                f"Namespace '{prefix}' is already declared. Choose a unique prefix."
            )
        self._namespaces[prefix] = NamespaceMetadata(
            prefix=prefix,
            description=description,
            loader=loader,
            loaded=loader is None,
        )

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, capability_id: str) -> Capability:
        """Retrieve a capability by its ID.

        If the capability ID falls under a declared namespace whose deferred
        loader has not yet run, the loader is invoked first.

        Args:
            capability_id: The capability's stable identifier.

        Returns:
            The matching :class:`Capability`.

        Raises:
            CapabilityNotFound: If no capability with that ID exists.
        """
        if capability_id not in self._store:
            self._maybe_load_for(capability_id)
        try:
            return self._store[capability_id]
        except KeyError:
            raise CapabilityNotFound(
                f"No capability registered with id='{capability_id}'. "
                "Check the capability_id or register it first."
            ) from None

    def list_all(self) -> list[Capability]:
        """Return every registered capability in registration order.

        Deferred-loader namespaces are *not* expanded by this call — to keep
        ``list_all`` cheap. Use :meth:`list_namespace` to force a load.
        """
        return list(self._store.values())

    # ── Namespaces ────────────────────────────────────────────────────────────

    def list_namespaces(self) -> list[str]:
        """Return every top-level namespace prefix present in the registry.

        Combines namespaces inferred from registered capability IDs with
        explicitly declared (:meth:`register_namespace`) prefixes. Returned
        sorted for deterministic output.
        """
        prefixes: set[str] = set()
        for cap_id in self._store:
            head, _, _ = cap_id.partition(".")
            prefixes.add(head)
        for ns in self._namespaces:
            prefixes.add(ns.split(".", 1)[0])
        return sorted(prefixes)

    def list_namespace(self, prefix: str) -> list[Capability]:
        """Return every capability whose ID lives under *prefix*.

        Triggers any deferred loader for *prefix* (or for the deepest declared
        ancestor of *prefix*) before returning. A capability_id ``cap`` is
        considered to live under ``prefix`` when ``cap == prefix`` or
        ``cap.startswith(prefix + ".")``.

        Args:
            prefix: Dot-notation namespace prefix.

        Returns:
            Capabilities under the prefix, in registration order.

        Raises:
            NamespaceNotFound: If no declared namespace or registered capability
                lives under *prefix*.
        """
        ancestor = self._deepest_declared_namespace(prefix)
        if ancestor is not None:
            self._maybe_load_namespace(ancestor)
        results = [
            cap
            for cap_id, cap in self._store.items()
            if cap_id == prefix or cap_id.startswith(prefix + ".")
        ]
        if not results and prefix not in self._namespaces:
            raise NamespaceNotFound(
                f"Namespace '{prefix}' has no registered capabilities and is not declared. "
                "Use register_namespace(prefix=...) or register a capability under it."
            )
        return results

    # ── Keyword matching ──────────────────────────────────────────────────────

    def search(
        self,
        goal: str,
        *,
        max_results: int = 10,
        offset: int = 0,
    ) -> list[CapabilityRequest]:
        """Search for capabilities matching *goal*.

        Tokenises *goal* (lower-cased word tokens, stop-words stripped) and
        scores every capability using a BM25-flavoured ranker that weights
        matches on ``capability_id`` and ``tags`` more heavily than
        ``description``. Capabilities tied on score are returned in
        ``capability_id`` order for determinism.

        Triggers every not-yet-loaded deferred namespace loader before scoring,
        so results span the full registry. Each loader runs at most once.

        Args:
            goal: Free-text description of the user's intent.
            max_results: Maximum number of results to return. Negative values
                are clamped to ``0`` (returns no results).
            offset: Number of leading results to skip (paginates large
                registries). Negative values are clamped to ``0``.

        Returns:
            Ordered list (highest score first) of :class:`CapabilityRequest`.
        """
        offset = max(offset, 0)
        max_results = max(max_results, 0)

        tokens = tokenize(goal)
        if not tokens:
            return []

        self._load_all_deferred_namespaces()

        ranked = self._index.ranked(self._store, tokens)
        if offset:
            ranked = ranked[offset:]
        return [
            CapabilityRequest(capability_id=cap.capability_id, goal=goal)
            for cap in ranked[:max_results]
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _deepest_declared_namespace(self, prefix: str) -> str | None:
        """Return the longest declared namespace owning *prefix*, else ``None``.

        ``ns`` owns *prefix* when ``prefix == ns`` or ``prefix.startswith(ns + ".")``;
        the deepest match's deferred loader is the one to run.
        """
        best: str | None = None
        for ns in self._namespaces:
            covers = prefix == ns or prefix.startswith(ns + ".")
            if covers and (best is None or len(ns) > len(best)):
                best = ns
        return best

    def _maybe_load_for(self, capability_id: str) -> None:
        """Trigger the deferred loader of the deepest namespace covering *capability_id*."""
        ancestor = self._deepest_declared_namespace(capability_id)
        if ancestor is not None:
            self._maybe_load_namespace(ancestor)

    def _maybe_load_namespace(self, prefix: str) -> None:
        """Invoke the deferred loader for *prefix* if it has not run yet.

        The batch is validated before anything registers: every returned
        ``capability_id`` must equal *prefix* or start with ``prefix + "."``. On
        violation nothing registers and the loaded flag resets for retry.

        Raises:
            FederationError: If the loader returns a capability whose
                ``capability_id`` does not live under *prefix*.
        """
        meta = self._namespaces.get(prefix)
        if meta is None or meta.loaded or meta.loader is None:
            return
        loader = meta.loader
        # Mark as loaded *before* calling so a recursive load doesn't re-enter.
        meta.loaded = True
        for cap in (loaded := list(loader())):
            cap_id = cap.capability_id
            if cap_id != prefix and not cap_id.startswith(prefix + "."):
                meta.loaded = False
                raise FederationError(
                    f"Namespace loader for '{prefix}' returned capability "
                    f"'{cap_id}', which does not live under the namespace. "
                    f"Loaders must return only capabilities whose capability_id "
                    f"equals '{prefix}' or starts with '{prefix}.'."
                )
        for cap in loaded:
            self.register(cap)

    def _load_all_deferred_namespaces(self) -> None:
        """Trigger every not-yet-loaded deferred loader (search ranks the whole registry)."""
        for prefix, meta in list(self._namespaces.items()):
            if not meta.loaded:
                self._maybe_load_namespace(prefix)
