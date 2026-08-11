"""Fail-closed safety classification for MCP tool discovery."""

from __future__ import annotations

import logging
from typing import Literal

from ..enums import SafetyClass
from ..errors import DriverError
from .mcp_support import ToolSpec

logger = logging.getLogger("weaver_kernel.drivers.mcp")

UnannotatedSafety = SafetyClass | Literal["reject"]
"""How discovery handles a tool with no usable MCP safety annotation."""


def infer_safety_class(spec: ToolSpec) -> SafetyClass | None:
    """Infer safety only from explicit MCP annotation hints.

    MCP annotations are advisory metadata, not authorization statements.
    Destructive wins if a server supplies conflicting read/destructive hints.
    Missing/ambiguous authority is represented as ``None`` rather than READ.
    """
    if spec.destructive_hint:
        return SafetyClass.DESTRUCTIVE
    if spec.read_only_hint:
        return SafetyClass.READ
    return None


def classify_tool_specs(
    specs: list[ToolSpec],
    *,
    driver_id: str,
    safety_class_map: dict[str, SafetyClass] | None,
    unannotated_safety: UnannotatedSafety,
) -> list[tuple[ToolSpec, SafetyClass]]:
    """Classify discovered MCP tools without silently granting unknown authority.

    Explicit operator mappings take precedence over advisory MCP annotations.
    Otherwise-unclassified tools are rejected by default; an explicit fallback
    is allowed but logged with every affected tool name.
    """
    if unannotated_safety != "reject" and not isinstance(unannotated_safety, SafetyClass):
        raise DriverError(
            "unannotated_safety must be 'reject' or a SafetyClass, "
            f"got {unannotated_safety!r}."
        )

    classified: list[tuple[ToolSpec, SafetyClass]] = []
    rejected: list[str] = []
    fallback: list[str] = []

    for spec in specs:
        if safety_class_map is not None and spec.name in safety_class_map:
            safety_class = safety_class_map[spec.name]
        else:
            inferred = infer_safety_class(spec)
            if inferred is not None:
                safety_class = inferred
            elif unannotated_safety == "reject":
                rejected.append(spec.name)
                continue
            else:
                safety_class = unannotated_safety
                fallback.append(spec.name)
        classified.append((spec, safety_class))

    if rejected:
        names = ", ".join(sorted(rejected))
        raise DriverError(
            f"MCPDriver '{driver_id}' refused to auto-register unclassified tools: {names}. "
            "Classify them with safety_class_map or explicitly set unannotated_safety to a "
            "SafetyClass. MCP annotations are advisory and missing metadata is not treated "
            "as READ authority."
        )

    if fallback:
        assert isinstance(unannotated_safety, SafetyClass)  # narrowed above
        logger.warning(
            "mcp_unannotated_safety_fallback driver_id=%s safety_class=%s tools=%s",
            driver_id,
            unannotated_safety.value,
            ",".join(sorted(fallback)),
        )

    return classified


__all__ = ["UnannotatedSafety", "classify_tool_specs", "infer_safety_class"]
