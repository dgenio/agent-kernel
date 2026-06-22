"""tiktoken-backed token counter for the context firewall (issue #218).

Implements the :class:`~weaver_kernel.firewall.token_counting.TokenCounter`
seam with a real tokenizer instead of the ``chars // 4`` heuristic, so
cross-invocation budgets count the same tokens an OpenAI-family model would.
Install the optional dependency with ``pip install weaver-kernel[tiktoken]``
and attach the counter to a :class:`~weaver_kernel.firewall.BudgetManager`::

    from weaver_kernel.firewall import BudgetManager, make_tiktoken_counter

    manager = BudgetManager(token_counter=make_tiktoken_counter())

``tiktoken`` is imported lazily inside the factory, never at module import
time, so importing :mod:`weaver_kernel` without the extra stays free of the
heavyweight dependency.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from ..errors import FirewallError
from .token_counting import TokenCounter

DEFAULT_ENCODING = "cl100k_base"
"""Default tiktoken encoding.

``cl100k_base`` covers GPT-4 / GPT-3.5-turbo and the ``text-embedding-3`` models
and is the broadest-compatibility choice. Pass ``encoding="o200k_base"`` for the
GPT-4o / o-series family. Anthropic models tokenize differently — name the
encoding explicitly for the model you budget against rather than relying on this
default.
"""


@lru_cache(maxsize=8)
def _load_encoding(name: str) -> Any:
    """Load and memoise a tiktoken encoding (constructing one is expensive).

    Args:
        name: A tiktoken encoding name, e.g. ``"cl100k_base"``.

    Returns:
        The tiktoken ``Encoding`` instance.

    Raises:
        ImportError: If the ``tiktoken`` extra is not installed.
        FirewallError: If *name* is not a known tiktoken encoding.
    """
    try:
        import tiktoken
    except ImportError as exc:
        raise ImportError(
            "tiktoken-based token counting requires the optional dependency "
            "'tiktoken>=0.6'. Install it with: pip install 'weaver-kernel[tiktoken]'"
        ) from exc
    try:
        return tiktoken.get_encoding(name)
    except (ValueError, KeyError) as exc:
        raise FirewallError(
            f"Unknown tiktoken encoding {name!r}; use a name such as "
            f"'cl100k_base' or 'o200k_base'."
        ) from exc


def make_tiktoken_counter(encoding: str = DEFAULT_ENCODING) -> TokenCounter:
    """Build a :class:`TokenCounter` that counts real tokens via tiktoken.

    The encoder is resolved (and cached) eagerly so a missing extra or an
    unknown encoding name fails at construction rather than on the first count.
    Counting is deterministic: strings are encoded directly; other values are
    rendered with ``json.dumps(..., default=str)`` first, mirroring the default
    counter's treatment of structured data.

    Args:
        encoding: tiktoken encoding name (see :data:`DEFAULT_ENCODING`).

    Returns:
        A callable implementing the :class:`TokenCounter` protocol.

    Raises:
        ImportError: If the ``tiktoken`` extra is not installed.
        FirewallError: If *encoding* is not a known tiktoken encoding.
    """
    _load_encoding(encoding)

    def count(value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, str):
            text = value
        else:
            try:
                text = json.dumps(value, default=str)
            except (TypeError, ValueError):
                text = str(value)
        return len(_load_encoding(encoding).encode(text))

    return count
