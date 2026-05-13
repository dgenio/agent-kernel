"""OpenAI tool-format adapter and middleware.

Supports both OpenAI tool-shape conventions:

- **Responses API** (default) — flat ``{"type": "function", "name", ...}`` tool
  definitions, ``function_call`` request items, ``function_call_output`` result
  items keyed by ``call_id``.
- **Chat Completions API** — nested ``{"type": "function", "function": {...}}``
  tool definitions, ``tool_calls[].function.arguments`` requests, ``{"role":
  "tool", "tool_call_id", "content"}`` result messages.

Tool-call shape is auto-detected on input regardless of the configured output
format.

No runtime dependency on the ``openai`` package — every public function takes
and returns plain dicts. Pydantic (a kernel runtime dep) handles schema
generation and argument validation.
"""

from __future__ import annotations

import json
import logging
import warnings
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from ..models import Capability, CapabilityRequest, ResponseMode
from ._base import (
    BaseToolMiddleware,
    PreparedCall,
    build_input_schema,
    error_to_payload,
    frame_to_payload,
    make_namespace_safe_name,
    normalize_for_openai_strict,
    restore_namespace,
)

if TYPE_CHECKING:
    from ..kernel import Kernel
    from ..models import Principal
    from ._base import ToolResultEvent

logger = logging.getLogger(__name__)

OpenAIToolFormat = Literal["responses", "chat_completions"]
"""Supported OpenAI tool/output shapes.

``responses`` matches the Responses API; ``chat_completions`` matches the
Chat Completions API. See module docstring for the per-format differences.
"""

_DEFAULT_FORMAT: OpenAIToolFormat = "responses"


# ── Schema conversion ─────────────────────────────────────────────────────────


def capabilities_to_tools(
    capabilities: list[Capability],
    *,
    format: OpenAIToolFormat = _DEFAULT_FORMAT,
) -> list[dict[str, Any]]:
    """Convert :class:`Capability` objects to OpenAI tool definitions.

    Args:
        capabilities: Capabilities to expose as tools.
        format: ``"responses"`` (default) emits flat Responses-API tool
            definitions; ``"chat_completions"`` emits nested Chat Completions
            tool definitions.

    Returns:
        Vendor-shaped tool definition dicts ready to pass to the OpenAI SDK.
    """
    return [_capability_to_tool(cap, format=format) for cap in capabilities]


def _capability_to_tool(capability: Capability, *, format: OpenAIToolFormat) -> dict[str, Any]:
    description = _describe(capability)
    parameters = build_input_schema(capability)
    name = make_namespace_safe_name(capability.capability_id)

    strict = bool(capability.tool_hints and capability.tool_hints.strict)
    if strict:
        try:
            parameters = normalize_for_openai_strict(parameters)
        except Exception as exc:  # noqa: BLE001 — fall back to non-strict
            warnings.warn(
                f"OpenAI strict-mode normalisation failed for '{capability.capability_id}'"
                f": {exc}. Emitting tool definition without strict.",
                stacklevel=2,
            )
            strict = False

    if format == "chat_completions":
        function: dict[str, Any] = {
            "name": name,
            "description": description,
            "parameters": parameters,
        }
        if strict:
            function["strict"] = True
        return {"type": "function", "function": function}

    # Responses API: flat shape.
    tool: dict[str, Any] = {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": parameters,
    }
    if strict:
        tool["strict"] = True
    return tool


def _describe(capability: Capability) -> str:
    """Build the user-facing description with safety/sensitivity context.

    Surfacing ``safety_class`` lets the LLM make better tool-choice decisions
    (e.g. avoid DESTRUCTIVE tools when a READ would suffice).
    """
    parts = [capability.description]
    parts.append(f"[safety={capability.safety_class.value}]")
    if capability.sensitivity.value != "NONE":
        parts.append(f"[sensitivity={capability.sensitivity.value}]")
    return " ".join(parts)


# ── Tool call → CapabilityRequest ─────────────────────────────────────────────


def tool_call_to_request(tool_call: dict[str, Any]) -> CapabilityRequest:
    """Convert an OpenAI tool call dict to a :class:`CapabilityRequest`.

    Auto-detects the input shape:

    - **Chat Completions:** ``{"id": "call_x", "type": "function",
      "function": {"name": "...", "arguments": "<json string>"}}``
    - **Responses:** ``{"type": "function_call", "call_id": "fc_x",
      "name": "...", "arguments": "<json string>"}``

    The ``arguments`` field is always a JSON-encoded string per the OpenAI
    spec; this function parses it.

    Raises:
        ValueError: If the dict shape isn't recognisable as either format,
            or if ``arguments`` is not valid JSON.
    """
    name, _ = _extract_name_and_call_id(tool_call)
    # Force-parse arguments so callers get the JSON-decode error here, not
    # later when the middleware tries to invoke. The parsed value is dropped:
    # ``CapabilityRequest`` carries the capability_id + goal only; args are
    # threaded through ``handle_tool_calls`` separately.
    _parse_arguments(tool_call.get("arguments"), tool_call)
    capability_id = restore_namespace(name)
    return CapabilityRequest(
        capability_id=capability_id,
        goal="adapter:openai",
        constraints={},
    )


def _extract_name_and_call_id(tool_call: dict[str, Any]) -> tuple[str, str]:
    """Return ``(function_name, call_id)`` regardless of input format."""
    fn = tool_call.get("function")
    if isinstance(fn, dict):
        # Chat Completions: nested function.{name, arguments}, id at top level.
        name = fn.get("name")
        call_id = tool_call.get("id", "")
    else:
        # Responses API: flat name/call_id/arguments at top level.
        name = tool_call.get("name")
        call_id = tool_call.get("call_id", "") or tool_call.get("id", "")
    if not isinstance(name, str) or not name:
        raise ValueError(
            "OpenAI tool_call is missing a function name. Expected either "
            "'function.name' (Chat Completions) or 'name' (Responses API)."
        )
    return name, str(call_id)


def _parse_arguments(raw: Any, tool_call: dict[str, Any]) -> dict[str, Any]:
    """Parse the JSON-encoded ``arguments`` field, with format fallback."""
    if raw is None:
        fn = tool_call.get("function")
        if isinstance(fn, dict):
            raw = fn.get("arguments")
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        # Some OpenAI clients pre-parse arguments; accept that shape too.
        return dict(raw)
    if not isinstance(raw, str):
        raise ValueError(
            f"OpenAI tool_call 'arguments' must be a JSON string or dict, got {type(raw).__name__}."
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"OpenAI tool_call 'arguments' is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            "OpenAI tool_call 'arguments' must decode to a JSON object (got "
            f"{type(parsed).__name__})."
        )
    return parsed


# ── Frame / error → OpenAI result ─────────────────────────────────────────────


def format_result(
    payload: dict[str, Any],
    *,
    call_id: str,
    format: OpenAIToolFormat = _DEFAULT_FORMAT,
) -> dict[str, Any]:
    """Wrap a payload dict in an OpenAI tool-result envelope.

    *payload* should already be the canonical kernel-result body produced by
    :func:`agent_kernel.adapters._base.frame_to_payload` or
    :func:`agent_kernel.adapters._base.error_to_payload`.
    """
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    if format == "chat_completions":
        return {"role": "tool", "tool_call_id": call_id, "content": body}
    return {"type": "function_call_output", "call_id": call_id, "output": body}


# ── Middleware ────────────────────────────────────────────────────────────────


class OpenAIMiddleware(BaseToolMiddleware):
    """Drop-in middleware for OpenAI Responses / Chat Completions tool use.

    Example::

        kernel = Kernel(registry=registry, ...)
        mw = OpenAIMiddleware(kernel, principal)
        tools = mw.get_tools()
        # ... pass tools to the OpenAI client ...
        outputs = await mw.handle_tool_calls(response.output)
    """

    vendor: ClassVar[Literal["openai", "anthropic"]] = "openai"

    def __init__(
        self,
        kernel: Kernel,
        principal: Principal,
        *,
        response_mode: ResponseMode = "summary",
        format: OpenAIToolFormat = _DEFAULT_FORMAT,
    ) -> None:
        super().__init__(kernel, principal, response_mode=response_mode)
        self._format: OpenAIToolFormat = format

    # ── Public API ─────────────────────────────────────────────────────────

    def get_tools(self) -> list[dict[str, Any]]:
        """Return every registered capability as an OpenAI tool definition."""
        return capabilities_to_tools(self._list_capabilities(), format=self._format)

    async def handle_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        justification: str = "",
    ) -> list[dict[str, Any]]:
        """Process a batch of OpenAI tool calls through the kernel pipeline.

        Args:
            tool_calls: Either ``response.output`` items from the Responses API
                (filtered or unfiltered — non-function items are passed
                through unchanged) or ``message.tool_calls`` items from the
                Chat Completions API. Input shape is auto-detected per call.
            justification: Justification applied to every call in the batch.
                Individual calls may override by including
                ``"_justification": "..."`` in their arguments.

        Returns:
            One vendor-shaped result envelope per *processed* tool call, in
            input order. Non-tool-call items in the input are skipped so the
            caller can stitch results back into the conversation as-is.
        """
        outputs: list[dict[str, Any]] = []
        for tool_call in tool_calls:
            if not _looks_like_tool_call(tool_call):
                continue
            try:
                name, call_id = _extract_name_and_call_id(tool_call)
                args = _parse_arguments(tool_call.get("arguments"), tool_call)
            except ValueError as exc:
                # Surface parse failures as a tool result so the LLM sees the
                # error rather than the agent loop crashing.
                outputs.append(
                    format_result(
                        error_to_payload(capability_id="<unknown>", error=str(exc)),
                        call_id=str(tool_call.get("id") or tool_call.get("call_id") or ""),
                        format=self._format,
                    )
                )
                continue

            prepared = PreparedCall(
                call_id=call_id,
                capability_id=restore_namespace(name),
                args=args,
            )
            event = await self._dispatch_one(prepared, batch_justification=justification)
            outputs.append(self._format_event(event))
        return outputs

    # ── Internal — vendor-shape result envelope ────────────────────────────

    def _format_event(self, event: ToolResultEvent) -> dict[str, Any]:
        if event.error is not None:
            payload = error_to_payload(capability_id=event.capability_id, error=event.error)
        else:
            # frame is guaranteed non-None when error is None.
            assert event.frame is not None
            payload = frame_to_payload(event.frame)
        return format_result(payload, call_id=event.call_id, format=self._format)


def _looks_like_tool_call(item: dict[str, Any]) -> bool:
    """Detect whether an item is an OpenAI function/tool call.

    Filters Responses-API output items that aren't function calls (e.g.
    text/message items) so the caller can pass ``response.output`` directly.
    """
    item_type = item.get("type")
    if item_type == "function_call":
        return True
    if item_type == "function":
        # Chat Completions style: tools list element. Function calls in
        # response messages also use type == "function".
        return True
    # Chat Completions sometimes omits "type" on tool_calls list entries
    # (depending on SDK version); fall back to detecting the nested function.
    return isinstance(item.get("function"), dict)


__all__ = [
    "OpenAIMiddleware",
    "OpenAIToolFormat",
    "capabilities_to_tools",
    "format_result",
    "tool_call_to_request",
]
