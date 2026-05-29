"""Version-consistency tests.

Pins the contract that ``agent_kernel.__version__`` is derived from the
installed distribution metadata rather than a hand-maintained literal, so it
can never drift from ``pyproject.toml`` again (issue #85). The PyPI
distribution name is ``weaver-kernel``, distinct from the import name
``agent_kernel``.
"""

from __future__ import annotations

import re
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest

import agent_kernel

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_pyproject_version() -> str | None:
    """Return ``[project].version`` from ``pyproject.toml``, or None if absent.

    Parsed with a small regex rather than ``tomllib`` so the test runs
    unchanged on Python 3.10 (where ``tomllib`` is unavailable) without adding
    a ``tomli`` dependency. Returns None when the source tree — and thus
    ``pyproject.toml`` — is not present (e.g. a wheel-only install).
    """
    if not _PYPROJECT.is_file():
        return None
    text = _PYPROJECT.read_text(encoding="utf-8")
    # Scope to the [project] table: from its header up to the next table header.
    section = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[)", text)
    body = section.group(1) if section else text
    match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', body)
    return match.group(1) if match else None


def test_version_matches_distribution_metadata() -> None:
    """``__version__`` equals the installed ``weaver-kernel`` dist version.

    Pins that ``__version__`` is *derived from* dist metadata (not a literal);
    cross-checking against ``pyproject.toml`` is done separately below.
    """
    assert agent_kernel.__version__ == pkg_version("weaver-kernel")


def test_version_matches_pyproject_declaration() -> None:
    """``__version__`` matches the version declared in ``pyproject.toml``.

    Directly enforces issue #85's acceptance criterion ("matches
    ``pyproject.toml``'s ``[project].version``") rather than only re-deriving
    from the same metadata source, so a release that bumps ``pyproject.toml``
    without refreshing the installed/editable metadata is caught.
    """
    declared = _declared_pyproject_version()
    if declared is None:
        pytest.skip("pyproject.toml not present (installed without source tree)")
    assert agent_kernel.__version__ == declared


def test_version_is_exported() -> None:
    """``__version__`` stays part of the public API surface."""
    assert "__version__" in agent_kernel.__all__
