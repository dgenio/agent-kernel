"""Capability registry: register, lookup, namespaced discovery, and ranked search.

Supports dot-notation namespaces (``"billing.invoices.list"``), deferred
namespace loaders for large tool ecosystems, and a BM25-flavoured score
that weights matches on ``capability_id`` and ``tags`` higher than
``description``. Flat (un-namespaced) capability IDs continue to work — they
are treated as living in a single-segment namespace.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable

from .errors import (
    CapabilityAlreadyRegistered,
    CapabilityNotFound,
    NamespaceNotFound,
)
from .models import Capability, CapabilityRequest, NamespaceMetadata

# Common English stop words that add noise to keyword search. Kept small
# (only words an LLM would routinely type into a goal) to avoid suppressing
# domain terms.
_STOP_WORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "get",
        "give",
        "i",
        "in",
        "is",
        "it",
        "me",
        "my",
        "of",
        "on",
        "or",
        "please",
        "show",
        "that",
        "the",
        "this",
        "to",
        "want",
        "with",
    }
)

# Field weights for BM25-flavoured scoring. Matches on capability_id and tags
# carry the most signal; description text is the noisiest.
_WEIGHT_ID = 4.0
_WEIGHT_NAME = 2.0
_WEIGHT_TAGS = 3.0
_WEIGHT_DESCRIPTION = 1.0

# BM25 tunables (Lucene defaults). Held constant — randomness in matching is
# forbidden by AGENTS.md.
_BM25_K1 = 1.5
_BM25_B = 0.75


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
        # Reset cached search statistics when registrations change.
        self._search_cache_dirty: bool = True
        self._avg_doc_len: float = 0.0
        self._doc_freq: dict[str, int] = {}

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
        self._search_cache_dirty = True

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
        self._maybe_load_namespace(prefix)
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

        Triggers any deferred namespace loader whose prefix overlaps the goal
        tokens before scoring.

        Args:
            goal: Free-text description of the user's intent.
            max_results: Maximum number of results to return.
            offset: Number of leading results to skip (paginates large
                registries).

        Returns:
            Ordered list (highest score first) of :class:`CapabilityRequest`.
        """
        tokens = self._tokenize(goal)
        if not tokens:
            return []

        self._load_namespaces_overlapping(tokens)

        if self._search_cache_dirty:
            self._rebuild_search_index()

        scored: list[tuple[float, Capability]] = []
        for cap in self._store.values():
            score = self._score(cap, tokens)
            if score > 0:
                scored.append((score, cap))

        scored.sort(key=lambda x: (-x[0], x[1].capability_id))

        if offset:
            scored = scored[offset:]
        return [
            CapabilityRequest(capability_id=cap.capability_id, goal=goal)
            for _, cap in scored[:max_results]
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Split *text* into lower-case word tokens with stop-words removed."""
        return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP_WORDS]

    @staticmethod
    def _corpus_fields(cap: Capability) -> tuple[list[str], list[str], list[str], list[str]]:
        """Return per-field token lists used for scoring (id, name, tags, description)."""
        tokenize = CapabilityRegistry._tokenize
        return (
            tokenize(cap.capability_id.replace(".", " ").replace("_", " ")),
            tokenize(cap.name),
            tokenize(" ".join(cap.tags)),
            tokenize(cap.description),
        )

    def _rebuild_search_index(self) -> None:
        """Refresh BM25 document statistics after the registry mutates."""
        total_len = 0
        doc_freq: dict[str, int] = {}
        for cap in self._store.values():
            id_tokens, name_tokens, tag_tokens, desc_tokens = self._corpus_fields(cap)
            total_len += len(id_tokens) + len(name_tokens) + len(tag_tokens) + len(desc_tokens)
            unique_tokens = set(id_tokens) | set(name_tokens) | set(tag_tokens) | set(desc_tokens)
            for tok in unique_tokens:
                doc_freq[tok] = doc_freq.get(tok, 0) + 1
        n = len(self._store) or 1
        self._avg_doc_len = total_len / n
        self._doc_freq = doc_freq
        self._search_cache_dirty = False

    def _score(self, cap: Capability, tokens: list[str]) -> float:
        """Return a BM25-flavoured match score for *cap* against query *tokens*."""
        id_tokens, name_tokens, tag_tokens, desc_tokens = self._corpus_fields(cap)
        doc_tokens = id_tokens + name_tokens + tag_tokens + desc_tokens
        if not doc_tokens:
            return 0.0
        doc_len = len(doc_tokens)
        n = len(self._store) or 1
        score = 0.0
        for tok in tokens:
            df = self._doc_freq.get(tok, 0)
            if df == 0:
                continue
            # Per-field term frequency with field-specific weights.
            tf = (
                _WEIGHT_ID * id_tokens.count(tok)
                + _WEIGHT_NAME * name_tokens.count(tok)
                + _WEIGHT_TAGS * tag_tokens.count(tok)
                + _WEIGHT_DESCRIPTION * desc_tokens.count(tok)
            )
            if tf == 0:
                continue
            idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
            norm = 1 - _BM25_B + _BM25_B * (doc_len / (self._avg_doc_len or 1.0))
            score += idf * ((tf * (_BM25_K1 + 1)) / (tf + _BM25_K1 * norm))
        # Exact-prefix bonus: capability_id starts with the joined query.
        joined = ".".join(tokens)
        if joined and cap.capability_id.startswith(joined):
            score += 1.0
        return score

    def _maybe_load_for(self, capability_id: str) -> None:
        """Trigger any deferred loader whose prefix covers *capability_id*."""
        head, _, _ = capability_id.partition(".")
        candidates = [head, capability_id]
        for prefix in candidates:
            if prefix in self._namespaces:
                self._maybe_load_namespace(prefix)

    def _maybe_load_namespace(self, prefix: str) -> None:
        """Invoke the deferred loader for *prefix* if it has not run yet."""
        meta = self._namespaces.get(prefix)
        if meta is None or meta.loaded or meta.loader is None:
            return
        loader = meta.loader
        # Mark as loaded *before* calling so a recursive load doesn't re-enter.
        meta.loaded = True
        for cap in loader():
            self.register(cap)

    def _load_namespaces_overlapping(self, tokens: list[str]) -> None:
        """Load any deferred namespace whose prefix shares a token with *tokens*."""
        token_set = set(tokens)
        for prefix, meta in list(self._namespaces.items()):
            if meta.loaded:
                continue
            head_tokens = set(self._tokenize(prefix.replace(".", " ").replace("_", " ")))
            if head_tokens & token_set:
                self._maybe_load_namespace(prefix)
