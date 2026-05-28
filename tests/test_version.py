"""Version-consistency tests.

Pins the contract that ``agent_kernel.__version__`` is derived from the
installed distribution metadata rather than a hand-maintained literal, so it
can never drift from ``pyproject.toml`` again (issue #85). The PyPI
distribution name is ``weaver-kernel``, distinct from the import name
``agent_kernel``.
"""

from __future__ import annotations

from importlib.metadata import version as pkg_version

import agent_kernel


def test_version_matches_distribution_metadata() -> None:
    """``__version__`` equals the installed ``weaver-kernel`` dist version."""
    assert agent_kernel.__version__ == pkg_version("weaver-kernel")


def test_version_is_exported() -> None:
    """``__version__`` stays part of the public API surface."""
    assert "__version__" in agent_kernel.__all__
