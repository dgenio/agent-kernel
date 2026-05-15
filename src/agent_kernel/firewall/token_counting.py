"""Token counting protocol and default character-based approximation.

The :class:`TokenCounter` protocol lets callers plug in vendor-specific
token counters (for example, a ``tiktoken``-based one) into the
:class:`~agent_kernel.firewall.budget_manager.BudgetManager`. The default
implementation, :func:`default_token_counter`, uses
``len(json.dumps(value, default=str)) // 4`` and has no extra dependencies.
"""

from __future__ import annotations

import json
from typing import Any, Protocol


class TokenCounter(Protocol):
    """Approximates the token cost of an arbitrary value.

    Implementations must be deterministic and side-effect-free.
    """

    def __call__(self, value: Any) -> int: ...


def default_token_counter(value: Any) -> int:
    """Character-based token approximation (``chars // 4``).

    Args:
        value: Any JSON-serialisable value. Non-serialisable values fall back
            to ``str(value)``.

    Returns:
        A non-negative integer approximating the token count.
    """
    if value is None:
        return 0
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return max(0, len(text) // 4)
