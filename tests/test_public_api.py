"""Public API consistency tests.

Pins the contract that the ``weaver_kernel`` module docstring's ``Errors::``
block stays in sync with the error classes actually exported via ``__all__``.
A newcomer who reads ``help(weaver_kernel)`` should see every public error
class, not a stale subset (issue #91).
"""

from __future__ import annotations

import re

import weaver_kernel
from weaver_kernel.errors import AgentKernelError


def _exported_error_names() -> list[str]:
    """Return every name in ``__all__`` that is an exported error class."""
    names: list[str] = []
    for name in weaver_kernel.__all__:
        obj = getattr(weaver_kernel, name)
        if isinstance(obj, type) and issubclass(obj, AgentKernelError):
            names.append(name)
    return names


def test_all_exported_errors_listed_in_module_docstring() -> None:
    """Every exported error class appears in the module docstring."""
    doc = weaver_kernel.__doc__ or ""
    # Use word-boundary matching so a shorter name (e.g. ``ManifestError``) is
    # not falsely considered present merely because it is a contiguous
    # substring of a longer listed name (e.g. ``ManifestSomethingError``).
    missing = [
        name for name in _exported_error_names() if not re.search(rf"\b{re.escape(name)}\b", doc)
    ]
    assert missing == [], (
        f"Error classes exported in __all__ but absent from the weaver_kernel "
        f"module docstring's 'Errors::' block: {missing}. Add them in "
        f"src/weaver_kernel/__init__.py so help(weaver_kernel) stays accurate."
    )
