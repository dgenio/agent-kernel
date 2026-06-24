"""Executable docstring examples for core public helpers (issue #195).

Inline doctests give the highest-traffic *synchronous* helpers runnable,
verified usage examples. The asynchronous core verbs (``request_capabilities``,
``grant_capability``, ``invoke``, ``expand``, ``explain``) are exercised end to
end by the example-based suite (``test_readme_quickstart``,
``test_chainweaver_flow``, ...) instead — async doctests with full kernel setup
would be unreadable, which the issue explicitly anticipates.
"""

from __future__ import annotations

import doctest
import importlib

# Modules whose docstrings carry runnable ``>>>`` examples. Keep this list
# curated: pointing doctest at modules with prose-only docstrings produces
# false failures.
_DOCTESTED_MODULES = [
    "weaver_kernel.firewall.token_counting",
    "weaver_kernel.firewall.size_estimate",
]


def test_public_doctests_pass() -> None:
    """Every curated module's doctests run and pass."""
    attempted = 0
    for module_name in _DOCTESTED_MODULES:
        module = importlib.import_module(module_name)
        result = doctest.testmod(module, verbose=False)
        assert result.failed == 0, f"{module_name}: {result.failed} doctest failure(s)"
        attempted += result.attempted
    assert attempted > 0, "No doctests were collected — the gate is not exercising anything."
