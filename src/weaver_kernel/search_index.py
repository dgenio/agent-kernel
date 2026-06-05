"""BM25-flavoured scoring index for capability search.

Extracted from :mod:`weaver_kernel.registry` to keep both modules within the
AGENTS.md 300-line budget. Scoring is pure and deterministic — no randomness is
used in matching (AGENTS.md). Matches on ``capability_id`` and ``tags`` are
weighted above ``description``.
"""

from __future__ import annotations

import math
import re

from .models import Capability

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


def tokenize(text: str) -> list[str]:
    """Split *text* into lower-case word tokens with stop-words removed."""
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP_WORDS]


def _corpus_fields(cap: Capability) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return per-field token lists used for scoring (id, name, tags, description)."""
    return (
        tokenize(cap.capability_id.replace(".", " ").replace("_", " ")),
        tokenize(cap.name),
        tokenize(" ".join(cap.tags)),
        tokenize(cap.description),
    )


class SearchIndex:
    """Maintains BM25 document statistics over a capability store.

    The index is rebuilt lazily: callers mark it dirty when the underlying
    store mutates, and :meth:`ranked` refreshes statistics on demand before
    scoring. The store itself is owned by the registry and passed in on each
    call so the index holds no duplicate capability state.
    """

    def __init__(self) -> None:
        self._dirty: bool = True
        self._avg_doc_len: float = 0.0
        self._doc_freq: dict[str, int] = {}

    def mark_dirty(self) -> None:
        """Invalidate cached statistics; they refresh on the next :meth:`ranked`."""
        self._dirty = True

    def ranked(self, store: dict[str, Capability], tokens: list[str]) -> list[Capability]:
        """Return capabilities matching *tokens*, highest score first.

        Capabilities tied on score are ordered by ``capability_id`` for
        determinism. Capabilities scoring zero are omitted.
        """
        if self._dirty:
            self._rebuild(store)
        n = len(store) or 1
        scored: list[tuple[float, Capability]] = []
        for cap in store.values():
            score = self._score(cap, tokens, n)
            if score > 0:
                scored.append((score, cap))
        scored.sort(key=lambda x: (-x[0], x[1].capability_id))
        return [cap for _, cap in scored]

    def _rebuild(self, store: dict[str, Capability]) -> None:
        """Refresh BM25 document statistics after the registry mutates."""
        total_len = 0
        doc_freq: dict[str, int] = {}
        for cap in store.values():
            id_tokens, name_tokens, tag_tokens, desc_tokens = _corpus_fields(cap)
            total_len += len(id_tokens) + len(name_tokens) + len(tag_tokens) + len(desc_tokens)
            unique_tokens = set(id_tokens) | set(name_tokens) | set(tag_tokens) | set(desc_tokens)
            for tok in unique_tokens:
                doc_freq[tok] = doc_freq.get(tok, 0) + 1
        n = len(store) or 1
        self._avg_doc_len = total_len / n
        self._doc_freq = doc_freq
        self._dirty = False

    def _score(self, cap: Capability, tokens: list[str], n: int) -> float:
        """Return a BM25-flavoured match score for *cap* against query *tokens*."""
        id_tokens, name_tokens, tag_tokens, desc_tokens = _corpus_fields(cap)
        doc_tokens = id_tokens + name_tokens + tag_tokens + desc_tokens
        if not doc_tokens:
            return 0.0
        doc_len = len(doc_tokens)
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
