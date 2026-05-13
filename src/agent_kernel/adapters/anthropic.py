"""Anthropic tool-format adapter and middleware.

Emits Anthropic Messages API tool definitions with optional ``cache_control``
support, and converts ``tool_use`` content blocks through the kernel pipeline
into ``tool_result`` content blocks.

Anthropic preserves dotted capability IDs as-is (their tool name field accepts
``[a-zA-Z0-9_.-]``), so no namespace transformation is required.

No runtime dependency on the ``anthropic`` package — every public function
takes and returns plain dicts. Pydantic (a kernel runtime dep) handles schema
generation and argument validation.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from ..models import Capability, CapabilityRequest, ResponseMode
from ._base import (
    BaseToolMiddleware,
    PreparedCall,
    build_input_schema,
    error_to_payload,
    frame_to_payload,
)

if TYPE_CHECKING:
    from ..kernel import Kernel
    from ..models import Principal
    from ._base import ToolResultEvent

logger = logging.getLogger(__name__)


# ── Schema conversion ─────────────────────────────────────────────────────────


def capabilities_to_tools(
    capabilities: list[Capability],
    *,
    default_cache_control: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Convert :class:`Capability` objects to Anthropic tool definitions.

    Args:
        capabilities: Capabilities to expose as tools.
        default_cache_control: Default ``cache_control`` block applied to every
            tool that does not specify its own via :attr:`Capability.tool_hints`.
            Per-capability ``ToolHints.cache_control`` takes precedence.

    Returns:
        List of dicts shaped like ``{"name", "description", "input_schema",
        "cache_control"?}`` ready to pass to the Anthropic SDK.
    """
    return [
        _capability_to_tool(cap, default_cache_control=default_cache_control)
        for cap in capabilities
    ]


def _capability_to_tool(
    capability: Capability,
    *,
    default_cache_control: dict[str, Any] | None,
) -> dict[str, Any]:
    tool: dict[str, Any] = {
        "name": capability.capability_id,
        "description": _describe(capability),
        "input_schema": build_input_schema(capability),
    }
    cache_control = _resolve_cache_control(capability, default_cache_control)
    if cache_control is not None:
        tool["cache_control"] = cache_control
    return tool


def _resolve_cache_control(
    capability: Capability,
    default_cache_control: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Per-capability ``cache_control`` from ``tool_hints`` wins over the default."""
    if capability.tool_hints is not None and capability.tool_hints.cache_control is not None:
        return dict(capability.tool_hints.cache_control)
    if default_cache_control is not None:
        return dict(default_cache_control)
    return None


def _describe(capability: Capability) -> str:
    """Build a description that surfaces safety/sensitivity to the LLM."""
    parts = [capability.description, f"[safety={capability.safety_class.value}]"]
    if capability.sensitivity.value != "NONE":
        parts.append(f"[sensitivity={capability.sensitivity.value}]")
    return " ".join(parts)


# ── tool_use → CapabilityRequest ──────────────────────────────────────────────


def tool_use_to_request(tool_use_block: dict[str, Any]) -> CapabilityRequest:
    """Convert an Anthropic ``tool_use`` content block to a :class:`CapabilityRequest`.

    Expected input shape::

        {"type": "tool_use", "id": "toolu_xxx", "name": "billing.list_invoices",
         "input": {"customer_id": "..."}}

    Anthropic delivers ``input`` as an object (not a JSON string), so no parsing
    is needed beyond a defensive copy.

    Raises:
        ValueError: If the block is missing ``name`` or ``input`` has the wrong type.
    """
    name = tool_use_block.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(
            "Anthropic tool_use block is missing a 'name' field or it is not a string."
        )
    raw_input = tool_use_block.get("input", {})
    if raw_input is None:
        raw_input = {}
    if not isinstance(raw_input, dict):
        raise ValueError(
            f"Anthropic tool_use 'input' must be an object (got {type(raw_input).__name__})."
        )
    return CapabilityRequest(
        capability_id=name,
        goal="adapter:anthropic",
        constraints={},
    )


# ── Frame / error → Anthropic tool_result ─────────────────────────────────────


def format_result(
    payload: dict[str, Any],
    *,
    tool_use_id: str,
    is_error: bool = False,
) -> dict[str, Any]:
    """Wrap a payload dict in an Anthropic ``tool_result`` content block.

    The payload is serialised to a single ``{"type": "text", "text": <json>}``
    content block so the LLM can reason over a stable, parseable shape and so
    downstream tool chains preserve content-block structure.
    """
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    block: dict[str, Any] = {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": [{"type": "text", "text": body}],
    }
    if is_error:
        block["is_error"] = True
    return block


# ── Middleware ────────────────────────────────────────────────────────────────


class AnthropicMiddleware(BaseToolMiddleware):
    """Drop-in middleware for Anthropic Messages tool use.

    Example::

        kernel = Kernel(registry=registry, ...)
        mw = AnthropicMiddleware(kernel, principal)
        tools = mw.get_tools()
        # ... pass tools to the Anthropic client ...
        tool_results = await mw.handle_tool_uses(message.content)
    """

    vendor: ClassVar[Literal["openai", "anthropic"]] = "anthropic"

    def __init__(
        self,
        kernel: Kernel,
        principal: Principal,
        *,
        response_mode: ResponseMode = "summary",
        default_cache_control: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(kernel, principal, response_mode=response_mode)
        self._default_cache_control = (
            dict(default_cache_control) if default_cache_control is not None else None
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def get_tools(self) -> list[dict[str, Any]]:
        """Return every registered capability as an Anthropic tool definition."""
        return capabilities_to_tools(
            self._list_capabilities(),
            default_cache_control=self._default_cache_control,
        )

    async def handle_tool_uses(
        self,
        content_blocks: list[dict[str, Any]],
        *,
        justification: str = "",
    ) -> list[dict[str, Any]]:
        """Process every ``tool_use`` block in *content_blocks* through the kernel.

        Args:
            content_blocks: An assistant message's ``content`` list. Non-
                ``tool_use`` blocks (text, etc.) are passed over so the caller
                can hand in raw ``message.content`` directly.
            justification: Justification applied to every call in the batch.
                Individual calls may override by including
                ``"_justification": "..."`` in their ``input``.

        Returns:
            One ``tool_result`` content block per processed ``tool_use``, in
            input order. Errors are returned as ``tool_result`` blocks with
            ``is_error: true`` rather than raised.
        """
        results: list[dict[str, Any]] = []
        for block in content_blocks:
            if block.get("type") != "tool_use":
                continue
            tool_use_id = str(block.get("id", ""))
            try:
                request = tool_use_to_request(block)
            except ValueError as exc:
                results.append(
                    format_result(
                        error_to_payload(capability_id="<unknown>", error=str(exc)),
                        tool_use_id=tool_use_id,
                        is_error=True,
                    )
                )
                continue

            raw_input = block.get("input") or {}
            # Defensive copy so hook mutation does not leak into the caller's data.
            args = dict(raw_input) if isinstance(raw_input, dict) else {}

            prepared = PreparedCall(
                call_id=tool_use_id,
                capability_id=request.capability_id,
                args=args,
            )
            event = await self._dispatch_one(prepared, batch_justification=justification)
            results.append(self._format_event(event))
        return results

    # ── Internal — vendor-shape result envelope ────────────────────────────

    def _format_event(self, event: ToolResultEvent) -> dict[str, Any]:
        if event.error is not None:
            payload = error_to_payload(capability_id=event.capability_id, error=event.error)
            return format_result(payload, tool_use_id=event.call_id, is_error=True)
        assert event.frame is not None
        payload = frame_to_payload(event.frame)
        return format_result(payload, tool_use_id=event.call_id, is_error=False)


__all__ = [
    "AnthropicMiddleware",
    "capabilities_to_tools",
    "format_result",
    "tool_use_to_request",
]
