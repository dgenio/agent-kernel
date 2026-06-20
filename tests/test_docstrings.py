"""Docstring-coverage gate for the public API (issue #195).

Pins the contract that every class and function exported via
``weaver_kernel.__all__`` carries a docstring meeting the documented shape:
a non-empty summary line, plus an ``Args:`` section for callables that take
parameters. A library whose generated docs site and IDE/copilot hints are
built from docstrings cannot afford an undocumented public symbol.

Type aliases (e.g. ``ResponseMode = Literal[...]``) and module-level
constants (``__version__``, ``OCSF_VERSION``, ...) cannot carry a meaningful
``__doc__`` and are documented in their module docstring instead, so they are
exempt from this gate.
"""

from __future__ import annotations

import inspect

import weaver_kernel


def _documentable_symbols() -> list[tuple[str, object]]:
    """Return ``(name, obj)`` for every class/function exported in ``__all__``."""
    out: list[tuple[str, object]] = []
    for name in weaver_kernel.__all__:
        obj = getattr(weaver_kernel, name)
        if inspect.isclass(obj) or inspect.isroutine(obj):
            out.append((name, obj))
    return out


def test_public_classes_and_functions_have_docstrings() -> None:
    """Every exported class/function has a non-empty docstring with a summary."""
    missing = [
        name for name, obj in _documentable_symbols() if not (inspect.getdoc(obj) or "").strip()
    ]
    assert missing == [], (
        f"Public symbols exported in __all__ without a docstring: {missing}. "
        f"Add a Google-style docstring in src/weaver_kernel/ so the generated "
        f"docs (#134) and IDE hints stay complete."
    )


def test_public_functions_document_their_parameters() -> None:
    """Exported functions that take parameters include an ``Args:`` section."""
    offenders: list[str] = []
    for name, obj in _documentable_symbols():
        if not inspect.isroutine(obj):
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        params = [
            p
            for p_name, p in sig.parameters.items()
            if p_name not in ("self", "cls") and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
        ]
        doc = inspect.getdoc(obj) or ""
        if params and "Args:" not in doc:
            offenders.append(name)
    assert offenders == [], (
        f"Exported functions with parameters but no 'Args:' section: {offenders}. "
        f"Document each parameter (Google-style) so the public contract is "
        f"self-describing."
    )
