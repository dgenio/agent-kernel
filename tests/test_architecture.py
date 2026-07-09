"""Automated architectural conformance checks (issue #202).

Two cheap, stdlib-only guards that preserve the documented layering without a
heavyweight architecture tool:

1. **Import boundaries.** Lower layers must not depend on higher ones. The
   rules below are derived from the *current* clean structure (see AGENTS.md
   "Architectural conformance"); they pass today and fail the moment a
   forbidden edge is introduced.
2. **Module-size ratchet.** Modules must stay within the documented 300-line
   budget (AGENTS.md). The files already over budget are listed explicitly
   with their current size as a ceiling, so they may only shrink — and any new
   or regrown module that crosses 300 lines fails immediately.

Both walk ``src/weaver_kernel`` with :mod:`ast`; no third-party dependency.
``TYPE_CHECKING`` and inside-function (lazy) imports are intentionally allowed —
the lazy seam is how optional extras stay optional.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "weaver_kernel"

# Leaf modules a given layer is allowed to import from within the package.
# Key = top-level module/sub-package under weaver_kernel; value = the only
# intra-package top-level names it may import. A layer absent from this map is
# unconstrained (e.g. ``kernel`` is the orchestrator and may import anything).
_ALLOWED_INTRA_IMPORTS: dict[str, set[str]] = {
    # The firewall transforms RawResult -> Frame using only the data contracts;
    # it must never reach back into execution/policy/registry layers.
    "firewall": {"models", "errors", "enums"},
    # Drivers execute capabilities and depend only on the data contracts.
    "drivers": {"models", "errors", "enums"},
    # The router is a stateless, import-light dispatch table.
    "router": {"models"},
    # Data contracts are leaves built only on enums + error types.
    "models": {"enums", "errors"},
    # Foundational leaves import nothing else in the package.
    "enums": set(),
    "errors": set(),
}

# Modules currently over the 300-line budget, with their present length as the
# ceiling (ratchet: these may shrink, never grow past this). Shrinking a module
# below 300 should remove it from this map. New modules are not allowed here.
_SIZE_RATCHET: dict[str, int] = {
    "__init__.py": 341,
    "models.py": 753,
    "policy.py": 652,
    "kernel/__init__.py": 541,
    "adapters/_base.py": 459,
    "kernel/_invoke.py": 390,
    "firewall/transform.py": 377,
    "adapters/openai.py": 358,
    "stores/sqlite.py": 350,
    "tokens.py": 336,
    "federation_discovery.py": 306,
}

_LINE_BUDGET = 300


def _rel(path: Path) -> str:
    return path.relative_to(_SRC).as_posix()


def _layer_of(rel_path: str) -> str:
    """Top-level module or sub-package name for a file under weaver_kernel."""
    head = rel_path.split("/", 1)[0]
    return head if "/" in rel_path else head.removesuffix(".py")


def _is_type_checking_guard(test: ast.expr) -> bool:
    """True for ``if TYPE_CHECKING:`` / ``if typing.TYPE_CHECKING:`` guards."""
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _module_scope_imports(body: list[ast.stmt]) -> list[ast.Import | ast.ImportFrom]:
    """Collect import statements at module scope.

    Descends into module-scope ``if`` / ``try`` / ``with`` blocks (so a
    conditional import cannot bypass the boundary check) but never into
    function or class bodies — those lazy imports are the optional-extra seam.
    The body of an ``if TYPE_CHECKING:`` guard is skipped (typing-only, never
    executed); its ``else`` branch *is* checked because it runs at runtime.
    """
    found: list[ast.Import | ast.ImportFrom] = []
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            found.append(node)
        elif isinstance(node, ast.If):
            if not _is_type_checking_guard(node.test):
                found.extend(_module_scope_imports(node.body))
            found.extend(_module_scope_imports(node.orelse))
        elif isinstance(node, ast.Try):
            found.extend(_module_scope_imports(node.body))
            for handler in node.handlers:
                found.extend(_module_scope_imports(handler.body))
            found.extend(_module_scope_imports(node.orelse))
            found.extend(_module_scope_imports(node.finalbody))
        elif isinstance(node, ast.With):
            found.extend(_module_scope_imports(node.body))
        # FunctionDef / AsyncFunctionDef / ClassDef: not descended (lazy seam).
    return found


def _intra_imports(tree: ast.Module, rel_path: str) -> set[str]:
    """Return top-level ``weaver_kernel`` names imported at *rel_path*'s scope.

    Relative imports are resolved against the importing file's package depth
    (``from .models`` in ``router.py`` and ``from ..models`` in
    ``firewall/transform.py`` both resolve to top-level ``models``), as are
    absolute ``weaver_kernel.<x>`` imports. Module-scope conditional imports
    (inside ``if`` / ``try`` / ``with``) are included; ``TYPE_CHECKING`` blocks
    and imports nested inside functions/classes are ignored — that lazy seam is
    how optional extras stay optional.
    """
    # Package parts of the importing module, e.g. firewall/transform.py -> ["firewall"].
    package_parts = rel_path.split("/")[:-1]
    base = ["weaver_kernel", *package_parts]

    names: set[str] = set()
    for node in _module_scope_imports(tree.body):
        if isinstance(node, ast.ImportFrom):
            if node.level > 0:
                # Drop (level - 1) trailing components to reach the target package.
                anchor = base[: len(base) - (node.level - 1)]
                resolved = [*anchor, *(node.module.split(".") if node.module else [])]
            elif node.module and node.module.startswith("weaver_kernel."):
                resolved = node.module.split(".")
            else:
                continue
            if len(resolved) >= 2 and resolved[0] == "weaver_kernel":
                names.add(resolved[1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("weaver_kernel."):
                    names.add(alias.name.split(".")[1])
    return names


def test_import_boundaries_hold() -> None:
    """No module imports outside its layer's allowed intra-package set."""
    violations: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        rel = _rel(path)
        layer = _layer_of(rel)
        allowed = _ALLOWED_INTRA_IMPORTS.get(layer)
        if allowed is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = _intra_imports(tree, rel)
        # A layer may always import within itself (e.g. firewall.transform ->
        # firewall.redaction shows up as the layer's own name or not at all).
        forbidden = {name for name in imported if name != layer and name not in allowed}
        if forbidden:
            violations.append(f"{rel} imports {sorted(forbidden)} (allowed: {sorted(allowed)})")
    assert violations == [], "Architectural import-boundary violations:\n" + "\n".join(violations)


def test_module_size_budget() -> None:
    """Every module is within 300 lines, or within its ratcheted ceiling."""
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        rel = _rel(path)
        lines = len(path.read_text(encoding="utf-8").splitlines())
        ceiling = _SIZE_RATCHET.get(rel, _LINE_BUDGET)
        if lines > ceiling:
            limit = "300-line budget" if rel not in _SIZE_RATCHET else f"ratchet ceiling {ceiling}"
            offenders.append(f"{rel}: {lines} lines exceeds {limit}")
    assert offenders == [], (
        "Module-size budget exceeded (split the module, or if you legitimately "
        "shrank an over-budget file, lower its ceiling in _SIZE_RATCHET):\n" + "\n".join(offenders)
    )
