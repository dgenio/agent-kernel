"""Tests for the tiktoken-backed token counter (issue #218).

These exercise the counter's own logic — value handling, encoder caching, and
error remapping — against a *fake* ``tiktoken`` module injected into
``sys.modules``. That keeps the suite deterministic and offline: the real
``tiktoken`` downloads its BPE vocabularies over the network on first use, which
must never be a test dependency (AGENTS.md prefers offline tests).
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator

import pytest

from weaver_kernel import FirewallError
from weaver_kernel.firewall import token_counting_tiktoken as tt


class _FakeEncoding:
    """Deterministic stand-in: one token per whitespace-separated word."""

    def encode(self, text: str) -> list[int]:
        return list(range(len(text.split())))


@pytest.fixture()
def fake_tiktoken(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    module = types.ModuleType("tiktoken")

    def get_encoding(name: str) -> _FakeEncoding:
        if name == "unknown-encoding":
            raise KeyError(name)
        return _FakeEncoding()

    module.get_encoding = get_encoding  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tiktoken", module)
    tt._load_encoding.cache_clear()
    yield
    tt._load_encoding.cache_clear()


def test_counts_words_as_tokens(fake_tiktoken: None) -> None:
    counter = tt.make_tiktoken_counter()
    assert counter("hello world") == 2


def test_none_is_zero(fake_tiktoken: None) -> None:
    assert tt.make_tiktoken_counter()(None) == 0


def test_structured_value_counts_serialised_form(fake_tiktoken: None) -> None:
    counter = tt.make_tiktoken_counter()
    # json.dumps({"id": 1}) == '{"id": 1}' → two whitespace-separated tokens.
    assert counter({"id": 1}) == 2


def test_non_serialisable_value_falls_back_to_str(fake_tiktoken: None) -> None:
    class Opaque:
        def __str__(self) -> str:
            return "one two three"

    assert tt.make_tiktoken_counter()(Opaque()) == 3


def test_explicit_encoding_is_accepted(fake_tiktoken: None) -> None:
    assert tt.make_tiktoken_counter(encoding="o200k_base")("a b c") == 3


def test_unknown_encoding_raises_firewall_error(fake_tiktoken: None) -> None:
    with pytest.raises(FirewallError):
        tt.make_tiktoken_counter(encoding="unknown-encoding")


def test_missing_extra_raises_helpful_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate the extra being absent: importing tiktoken raises ModuleNotFoundError.
    monkeypatch.setitem(sys.modules, "tiktoken", None)
    tt._load_encoding.cache_clear()
    with pytest.raises(ImportError, match=r"weaver-kernel\[tiktoken\]"):
        tt.make_tiktoken_counter()
    tt._load_encoding.cache_clear()


def test_wires_into_budget_manager(fake_tiktoken: None) -> None:
    from weaver_kernel.firewall import BudgetManager

    manager = BudgetManager(total_budget=1000, token_counter=tt.make_tiktoken_counter())
    assert manager.count_tokens("hello world") == 2
