"""Tests for LLM tool-format adapters (OpenAI + Anthropic).

Adapters are pure dict transforms with a thin async middleware on top. These
tests exercise both pieces without depending on the ``openai`` or
``anthropic`` SDKs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import BaseModel, Field

from agent_kernel import (
    AdapterParseError,
    AnthropicMiddleware,
    Capability,
    CapabilityRegistry,
    Kernel,
    OpenAIMiddleware,
    Principal,
    SafetyClass,
    SensitivityTag,
    ToolHints,
)
from agent_kernel.adapters import (
    ToolCallEvent,
    ToolResultEvent,
)
from agent_kernel.adapters import (
    anthropic as anthropic_mod,
)
from agent_kernel.adapters import (
    openai as openai_mod,
)
from agent_kernel.adapters._base import (
    build_input_schema,
    error_to_payload,
    frame_to_payload,
    make_namespace_safe_name,
    normalize_for_openai_strict,
    restore_namespace,
    validate_input,
)
from agent_kernel.models import CapabilityRequest

# ── Helpers ───────────────────────────────────────────────────────────────────


class _InvoiceArgs(BaseModel):
    """Schema model used to validate billing.list_invoices arguments."""

    operation: str = Field(default="list_invoices")
    customer_id: str
    limit: int = Field(default=10, ge=1, le=100)


def _cap_with_model(cap_id: str = "billing.list_invoices") -> Capability:
    return Capability(
        capability_id=cap_id,
        name="List Invoices",
        description="List invoices for a customer",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.PII,
        parameters_model=_InvoiceArgs,
    )


# ── Capability model extensions ───────────────────────────────────────────────


def test_capability_defaults_preserve_backward_compat() -> None:
    """New fields all default to None — existing constructors keep working."""
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
    )
    assert cap.parameters_model is None
    assert cap.parameters_schema is None
    assert cap.tool_hints is None


def test_tool_hints_dataclass_defaults() -> None:
    hints = ToolHints()
    assert hints.cache_control is None
    assert hints.strict is False


# ── Schema helpers (_base) ────────────────────────────────────────────────────


def test_build_input_schema_uses_parameters_model() -> None:
    cap = _cap_with_model()
    schema = build_input_schema(cap)
    assert schema["type"] == "object"
    assert set(schema["properties"].keys()) == {"operation", "customer_id", "limit"}
    # Pydantic emits required for fields without defaults.
    assert schema["required"] == ["customer_id"]


def test_build_input_schema_uses_parameters_schema_fallback() -> None:
    raw = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
        parameters_schema=raw,
    )
    schema = build_input_schema(cap)
    assert schema == raw
    # build_input_schema copies — mutating the result must not bleed into the capability.
    schema["properties"]["x"]["type"] = "integer"
    assert cap.parameters_schema is not None
    assert cap.parameters_schema["properties"]["x"]["type"] == "string"


def test_build_input_schema_permissive_default() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
    )
    schema = build_input_schema(cap)
    assert schema == {"type": "object", "additionalProperties": True}


def test_normalize_for_openai_strict_required_and_no_additional() -> None:
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": {
                "type": "object",
                "properties": {"c": {"type": "integer"}},
            },
        },
    }
    out = normalize_for_openai_strict(schema)
    assert out["required"] == ["a", "b"]
    assert out["additionalProperties"] is False
    # Recursive: nested object also gets the treatment.
    assert out["properties"]["b"]["required"] == ["c"]
    assert out["properties"]["b"]["additionalProperties"] is False
    # Original is untouched.
    assert "required" not in schema
    assert "additionalProperties" not in schema


def test_validate_input_passes_through_without_model() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
    )
    args = {"anything": "goes"}
    assert validate_input(cap, args) == args


def test_validate_input_with_model_coerces_and_returns_dict() -> None:
    cap = _cap_with_model()
    out = validate_input(cap, {"customer_id": "c-1", "limit": "5"})
    assert out["customer_id"] == "c-1"
    assert out["limit"] == 5  # pydantic coerced str → int
    assert out["operation"] == "list_invoices"


def test_validate_input_with_model_raises_on_bad_args() -> None:
    from pydantic import ValidationError

    cap = _cap_with_model()
    with pytest.raises(ValidationError):
        validate_input(cap, {"limit": 5})  # missing customer_id


# ── Namespace helpers ─────────────────────────────────────────────────────────


def test_namespace_round_trip() -> None:
    original = "billing.list_invoices"
    safe = make_namespace_safe_name(original)
    assert safe == "billing__list_invoices"
    assert restore_namespace(safe) == original


def test_namespace_preserves_single_underscores() -> None:
    """Capabilities with underscores in segments must round-trip unambiguously."""
    original = "billing.list_invoices_v2"
    assert restore_namespace(make_namespace_safe_name(original)) == original


def test_namespace_rejects_capability_id_with_reserved_separator() -> None:
    """``__`` in a capability_id collides with the OpenAI namespace separator.

    ``"a__b"`` and ``"a.b"`` would both map to OpenAI tool name ``"a__b"`` —
    a silent collision. ``make_namespace_safe_name`` rejects the input rather
    than producing a colliding tool name.
    """
    with pytest.raises(AdapterParseError, match="reserved namespace separator"):
        make_namespace_safe_name("a__b")


def test_namespace_collision_surfaces_via_capabilities_to_tools() -> None:
    """An invalid capability_id surfaces at adapter-emit time.

    The validation lives in ``make_namespace_safe_name``; callers exercising
    the public OpenAI schema-conversion function see the same error.
    """
    cap = Capability(
        capability_id="a__b",
        name="Bad",
        description="d",
        safety_class=SafetyClass.READ,
    )
    with pytest.raises(AdapterParseError, match="reserved namespace separator"):
        openai_mod.capabilities_to_tools([cap])


# ── Payload helpers ───────────────────────────────────────────────────────────


def test_error_to_payload_shape() -> None:
    payload = error_to_payload(capability_id="x.y", error="boom")
    assert payload == {"error": True, "capability_id": "x.y", "message": "boom"}


# ── OpenAI: schema conversion ─────────────────────────────────────────────────


def test_openai_capabilities_to_tools_responses_format() -> None:
    cap = _cap_with_model()
    tools = openai_mod.capabilities_to_tools([cap])
    assert len(tools) == 1
    tool = tools[0]
    assert tool["type"] == "function"
    assert tool["name"] == "billing__list_invoices"
    assert "[safety=READ]" in tool["description"]
    assert "[sensitivity=PII]" in tool["description"]
    assert tool["parameters"]["type"] == "object"
    # No nested function key in Responses-API shape.
    assert "function" not in tool


def test_openai_capabilities_to_tools_chat_completions_format() -> None:
    cap = _cap_with_model()
    tools = openai_mod.capabilities_to_tools([cap], format="chat_completions")
    assert len(tools) == 1
    tool = tools[0]
    assert tool["type"] == "function"
    assert "function" in tool
    assert tool["function"]["name"] == "billing__list_invoices"
    assert tool["function"]["parameters"]["type"] == "object"
    # No flat name in Chat-Completions shape.
    assert "name" not in tool


def test_openai_strict_mode_emits_strict_flag_and_normalises_schema() -> None:
    cap = Capability(
        capability_id="billing.update_invoice",
        name="Update",
        description="d",
        safety_class=SafetyClass.WRITE,
        parameters_model=_InvoiceArgs,
        tool_hints=ToolHints(strict=True),
    )
    tool = openai_mod.capabilities_to_tools([cap])[0]
    assert tool["strict"] is True
    # Strict normalisation forces every property required and additionalProperties=false.
    assert tool["parameters"]["additionalProperties"] is False
    assert set(tool["parameters"]["required"]) == {"operation", "customer_id", "limit"}


def test_openai_description_omits_sensitivity_when_none() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
    )
    tool = openai_mod.capabilities_to_tools([cap])[0]
    assert "[safety=READ]" in tool["description"]
    assert "[sensitivity=" not in tool["description"]


# ── OpenAI: tool_call → CapabilityRequest ─────────────────────────────────────


def test_openai_tool_call_to_request_chat_completions_shape() -> None:
    tool_call = {
        "id": "call_abc",
        "type": "function",
        "function": {
            "name": "billing__list_invoices",
            "arguments": json.dumps({"customer_id": "c-1"}),
        },
    }
    req = openai_mod.tool_call_to_request(tool_call)
    assert isinstance(req, CapabilityRequest)
    assert req.capability_id == "billing.list_invoices"


def test_openai_tool_call_to_request_responses_shape() -> None:
    tool_call = {
        "type": "function_call",
        "call_id": "fc_xyz",
        "name": "billing__list_invoices",
        "arguments": json.dumps({"customer_id": "c-1"}),
    }
    req = openai_mod.tool_call_to_request(tool_call)
    assert req.capability_id == "billing.list_invoices"


def test_openai_tool_call_to_request_raises_on_invalid_json() -> None:
    tool_call = {
        "type": "function_call",
        "call_id": "fc_xyz",
        "name": "billing__list_invoices",
        "arguments": "{not valid",
    }
    with pytest.raises(AdapterParseError, match="not valid JSON"):
        openai_mod.tool_call_to_request(tool_call)


def test_openai_tool_call_to_request_raises_on_missing_name() -> None:
    with pytest.raises(AdapterParseError, match="missing a function name"):
        openai_mod.tool_call_to_request({"id": "x", "type": "function", "function": {}})


# ── OpenAI middleware: end-to-end ─────────────────────────────────────────────


def test_openai_get_tools_lists_all_registered_capabilities(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = OpenAIMiddleware(kernel, reader_principal)
    tools = mw.get_tools()
    names = {t["name"] for t in tools}
    assert "billing__list_invoices" in names
    assert "billing__update_invoice" in names  # WRITE capability still listed


@pytest.mark.asyncio
async def test_openai_handle_tool_calls_success_flow(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = OpenAIMiddleware(kernel, reader_principal)
    tool_calls = [
        {
            "type": "function_call",
            "call_id": "fc_1",
            "name": "billing__list_invoices",
            "arguments": json.dumps({"operation": "billing.list_invoices"}),
        }
    ]
    outputs = await mw.handle_tool_calls(tool_calls)
    assert len(outputs) == 1
    out = outputs[0]
    assert out["type"] == "function_call_output"
    assert out["call_id"] == "fc_1"
    payload = json.loads(out["output"])
    assert payload["capability_id"] == "billing.list_invoices"
    assert payload["response_mode"] == "summary"
    assert "error" not in payload


@pytest.mark.asyncio
async def test_openai_handle_tool_calls_policy_denied_surfaces_as_error(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """A WRITE call by a reader becomes a tool-result error, not a raised exception."""
    mw = OpenAIMiddleware(kernel, reader_principal)
    tool_calls = [
        {
            "type": "function_call",
            "call_id": "fc_deny",
            "name": "billing__update_invoice",
            "arguments": json.dumps({}),
        }
    ]
    outputs = await mw.handle_tool_calls(tool_calls, justification="long enough justification")
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "Policy denied" in payload["message"]


@pytest.mark.asyncio
async def test_openai_handle_tool_calls_unknown_capability_surfaces_as_error(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = OpenAIMiddleware(kernel, reader_principal)
    tool_calls = [
        {
            "type": "function_call",
            "call_id": "fc_unknown",
            "name": "nonexistent__capability",
            "arguments": "{}",
        }
    ]
    outputs = await mw.handle_tool_calls(tool_calls)
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "not registered" in payload["message"]


@pytest.mark.asyncio
async def test_openai_handle_tool_calls_invalid_json_arguments_surfaces_as_error(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = OpenAIMiddleware(kernel, reader_principal)
    tool_calls = [
        {
            "type": "function_call",
            "call_id": "fc_bad",
            "name": "billing__list_invoices",
            "arguments": "{not valid",
        }
    ]
    outputs = await mw.handle_tool_calls(tool_calls)
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "not valid JSON" in payload["message"]


@pytest.mark.asyncio
async def test_openai_handle_tool_calls_skips_non_function_items(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """Non-function items in response.output are silently skipped."""
    mw = OpenAIMiddleware(kernel, reader_principal)
    output = await mw.handle_tool_calls(
        [
            {"type": "message", "content": "thinking..."},
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            },
        ]
    )
    assert len(output) == 1
    assert output[0]["call_id"] == "fc_1"


@pytest.mark.asyncio
async def test_openai_chat_completions_output_shape(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = OpenAIMiddleware(kernel, reader_principal, format="chat_completions")
    outputs = await mw.handle_tool_calls(
        [
            {
                "id": "call_chat",
                "type": "function",
                "function": {
                    "name": "billing__list_invoices",
                    "arguments": "{}",
                },
            }
        ]
    )
    assert outputs[0]["role"] == "tool"
    assert outputs[0]["tool_call_id"] == "call_chat"
    assert "content" in outputs[0]


# ── OpenAI middleware: hooks ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_openai_hooks_fire_in_registration_order(
    kernel: Kernel, reader_principal: Principal
) -> None:
    seen: list[str] = []
    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_call(lambda e: seen.append(f"pre1:{e.capability_id}"))
    mw.intercept_tool_call(lambda e: seen.append(f"pre2:{e.capability_id}"))
    mw.intercept_tool_result(lambda e: seen.append(f"post1:{e.capability_id}"))
    mw.intercept_tool_result(lambda e: seen.append(f"post2:{e.capability_id}"))

    await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            }
        ]
    )
    assert seen == [
        "pre1:billing.list_invoices",
        "pre2:billing.list_invoices",
        "post1:billing.list_invoices",
        "post2:billing.list_invoices",
    ]


@pytest.mark.asyncio
async def test_openai_hooks_support_async_callables(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """Async hooks are awaited; sync and async can be mixed in the same registration."""
    seen: list[str] = []

    async def async_pre(event: ToolCallEvent) -> None:
        seen.append(f"async_pre:{event.capability_id}")

    def sync_pre(event: ToolCallEvent) -> None:
        seen.append(f"sync_pre:{event.capability_id}")

    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_call(async_pre)
    mw.intercept_tool_call(sync_pre)
    await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            }
        ]
    )
    assert seen == ["async_pre:billing.list_invoices", "sync_pre:billing.list_invoices"]


@pytest.mark.asyncio
async def test_openai_pre_hook_can_abort(kernel: Kernel, reader_principal: Principal) -> None:
    """Pre-hook setting aborted=True short-circuits without invoking the kernel."""

    def gate(event: ToolCallEvent) -> None:
        event.aborted = True
        event.abort_reason = "manual approval required"

    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_call(gate)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            }
        ]
    )
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "Aborted by pre-invocation hook" in payload["message"]
    assert "manual approval required" in payload["message"]


@pytest.mark.asyncio
async def test_openai_pre_hook_injects_justification_for_write(
    kernel: Kernel, reader_principal: Principal, writer_principal: Principal
) -> None:
    """A pre-hook can inject a justification so a WRITE call satisfies policy."""

    def inject(event: ToolCallEvent) -> None:
        event.justification = "approved by reviewer 12345 with sufficient length"

    mw = OpenAIMiddleware(kernel, writer_principal)
    mw.intercept_tool_call(inject)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__update_invoice",
                "arguments": json.dumps({"operation": "billing.update_invoice"}),
            }
        ]
    )
    payload = json.loads(outputs[0]["output"])
    assert payload.get("error") is None
    assert payload["capability_id"] == "billing.update_invoice"


@pytest.mark.asyncio
async def test_openai_per_call_justification_override(
    kernel: Kernel, writer_principal: Principal
) -> None:
    """Per-call _justification in args overrides the batch justification."""
    mw = OpenAIMiddleware(kernel, writer_principal)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__update_invoice",
                "arguments": json.dumps(
                    {
                        "operation": "billing.update_invoice",
                        "_justification": "per-call long enough justification",
                    }
                ),
            }
        ],
        justification="short",  # would fail if used
    )
    payload = json.loads(outputs[0]["output"])
    assert payload.get("error") is None


@pytest.mark.asyncio
async def test_openai_post_hook_observes_frame(
    kernel: Kernel, reader_principal: Principal
) -> None:
    captured: list[ToolResultEvent] = []
    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_result(lambda e: captured.append(e))
    await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            }
        ]
    )
    assert len(captured) == 1
    assert captured[0].frame is not None
    assert captured[0].error is None
    assert captured[0].capability_id == "billing.list_invoices"


# ── Anthropic: schema conversion ──────────────────────────────────────────────


def test_anthropic_capabilities_to_tools_preserves_dotted_id() -> None:
    cap = _cap_with_model()
    tools = anthropic_mod.capabilities_to_tools([cap])
    assert len(tools) == 1
    tool = tools[0]
    # Anthropic preserves dots — no namespace transformation.
    assert tool["name"] == "billing.list_invoices"
    assert "input_schema" in tool
    assert tool["input_schema"]["type"] == "object"
    assert "cache_control" not in tool  # no default, no per-cap hint


def test_anthropic_capabilities_to_tools_per_capability_cache_control() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
        tool_hints=ToolHints(cache_control={"type": "ephemeral"}),
    )
    tool = anthropic_mod.capabilities_to_tools([cap])[0]
    assert tool["cache_control"] == {"type": "ephemeral"}


def test_anthropic_capabilities_to_tools_default_cache_control_applied() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
    )
    tool = anthropic_mod.capabilities_to_tools([cap], default_cache_control={"type": "ephemeral"})[
        0
    ]
    assert tool["cache_control"] == {"type": "ephemeral"}


def test_anthropic_capabilities_to_tools_per_capability_overrides_default() -> None:
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
        tool_hints=ToolHints(cache_control={"type": "static"}),
    )
    tool = anthropic_mod.capabilities_to_tools([cap], default_cache_control={"type": "ephemeral"})[
        0
    ]
    assert tool["cache_control"] == {"type": "static"}


# ── Anthropic: tool_use → CapabilityRequest ───────────────────────────────────


def test_anthropic_tool_use_to_request_preserves_dotted_id() -> None:
    block = {
        "type": "tool_use",
        "id": "toolu_xyz",
        "name": "billing.list_invoices",
        "input": {"customer_id": "c-1"},
    }
    req = anthropic_mod.tool_use_to_request(block)
    assert req.capability_id == "billing.list_invoices"


def test_anthropic_tool_use_to_request_raises_on_missing_name() -> None:
    with pytest.raises(AdapterParseError, match="missing a 'name'"):
        anthropic_mod.tool_use_to_request({"type": "tool_use", "id": "x", "input": {}})


def test_anthropic_tool_use_to_request_raises_on_non_dict_input() -> None:
    with pytest.raises(AdapterParseError, match="must be an object"):
        anthropic_mod.tool_use_to_request(
            {"type": "tool_use", "id": "x", "name": "n", "input": "string"}
        )


# ── Anthropic middleware: end-to-end ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_anthropic_handle_tool_uses_success_flow(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = AnthropicMiddleware(kernel, reader_principal)
    blocks = [
        {
            "type": "tool_use",
            "id": "toolu_1",
            "name": "billing.list_invoices",
            "input": {"operation": "billing.list_invoices"},
        }
    ]
    results = await mw.handle_tool_uses(blocks)
    assert len(results) == 1
    r = results[0]
    assert r["type"] == "tool_result"
    assert r["tool_use_id"] == "toolu_1"
    assert r.get("is_error") is None or r["is_error"] is False
    text_block = r["content"][0]
    assert text_block["type"] == "text"
    payload = json.loads(text_block["text"])
    assert payload["capability_id"] == "billing.list_invoices"


@pytest.mark.asyncio
async def test_anthropic_handle_tool_uses_skips_text_blocks(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = AnthropicMiddleware(kernel, reader_principal)
    results = await mw.handle_tool_uses(
        [
            {"type": "text", "text": "thinking..."},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "billing.list_invoices",
                "input": {},
            },
        ]
    )
    assert len(results) == 1
    assert results[0]["tool_use_id"] == "toolu_1"


@pytest.mark.asyncio
async def test_anthropic_handle_tool_uses_policy_denied_is_error_block(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = AnthropicMiddleware(kernel, reader_principal)
    results = await mw.handle_tool_uses(
        [
            {
                "type": "tool_use",
                "id": "toolu_deny",
                "name": "billing.update_invoice",
                "input": {},
            }
        ],
        justification="long enough justification",
    )
    assert results[0]["is_error"] is True
    payload = json.loads(results[0]["content"][0]["text"])
    assert payload["error"] is True
    assert "Policy denied" in payload["message"]


@pytest.mark.asyncio
async def test_anthropic_handle_tool_uses_unknown_capability_is_error_block(
    kernel: Kernel, reader_principal: Principal
) -> None:
    mw = AnthropicMiddleware(kernel, reader_principal)
    results = await mw.handle_tool_uses(
        [{"type": "tool_use", "id": "toolu_x", "name": "nope.nada", "input": {}}]
    )
    assert results[0]["is_error"] is True
    payload = json.loads(results[0]["content"][0]["text"])
    assert "not registered" in payload["message"]


# ── Anthropic hooks ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_anthropic_hooks_fire_in_registration_order(
    kernel: Kernel, reader_principal: Principal
) -> None:
    seen: list[str] = []
    mw = AnthropicMiddleware(kernel, reader_principal)
    mw.intercept_tool_call(lambda e: seen.append(f"pre:{e.vendor}"))
    mw.intercept_tool_result(lambda e: seen.append(f"post:{e.vendor}"))
    await mw.handle_tool_uses(
        [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "billing.list_invoices",
                "input": {},
            }
        ]
    )
    assert seen == ["pre:anthropic", "post:anthropic"]


# ── Shared: validation, frame_to_payload ──────────────────────────────────────


@pytest.mark.asyncio
async def test_middleware_input_validation_surfaces_as_tool_error(
    reader_principal: Principal,
) -> None:
    """When a capability has parameters_model, bad args become a tool-result error."""
    cap = _cap_with_model()
    registry = CapabilityRegistry()
    registry.register(cap)

    from agent_kernel import HMACTokenProvider, InMemoryDriver, StaticRouter
    from agent_kernel.drivers.base import ExecutionContext

    driver = InMemoryDriver(driver_id="memory")

    def echo(ctx: ExecutionContext) -> dict[str, Any]:
        return {"echo": ctx.args}

    driver.register_handler("billing.list_invoices", echo)
    driver.register_handler("list_invoices", echo)
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret"),
        router=StaticRouter(routes={"billing.list_invoices": ["memory"]}),
    )
    kernel.register_driver(driver)

    mw = OpenAIMiddleware(kernel, reader_principal)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_bad",
                "name": "billing__list_invoices",
                "arguments": json.dumps({"limit": 5}),  # missing required customer_id
            }
        ]
    )
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "validation failed" in payload["message"].lower()


@pytest.mark.asyncio
async def test_pre_hook_exception_becomes_tool_error(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """A pre-hook that raises does not crash the batch — it becomes a tool error."""

    def bad(event: ToolCallEvent) -> None:
        raise RuntimeError("pre-hook explosion")

    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_call(bad)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "{}",
            }
        ]
    )
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "Pre-invocation hook raised" in payload["message"]
    assert "pre-hook explosion" in payload["message"]


@pytest.mark.asyncio
async def test_post_hook_exception_is_logged_not_raised(
    kernel: Kernel, reader_principal: Principal, caplog: pytest.LogCaptureFixture
) -> None:
    """A post-hook that raises is logged but never crashes the batch."""

    def bad(event: ToolResultEvent) -> None:
        raise RuntimeError("post-hook explosion")

    mw = OpenAIMiddleware(kernel, reader_principal)
    mw.intercept_tool_result(bad)
    with caplog.at_level("WARNING", logger="agent_kernel.adapters._base"):
        outputs = await mw.handle_tool_calls(
            [
                {
                    "type": "function_call",
                    "call_id": "fc_1",
                    "name": "billing__list_invoices",
                    "arguments": "{}",
                }
            ]
        )
    # The call still succeeded — only the hook failed.
    payload = json.loads(outputs[0]["output"])
    assert payload.get("error") is None
    assert any("post_hook_failed" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_driver_error_surfaces_as_tool_error(reader_principal: Principal) -> None:
    """A DriverError is converted to a tool-result error, not raised."""
    from agent_kernel import HMACTokenProvider, InMemoryDriver, StaticRouter
    from agent_kernel.drivers.base import ExecutionContext
    from agent_kernel.errors import DriverError

    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="explode.now",
            name="Explode",
            description="d",
            safety_class=SafetyClass.READ,
        )
    )

    def explode(ctx: ExecutionContext) -> dict[str, Any]:
        raise DriverError("driver fell over")

    driver = InMemoryDriver(driver_id="memory")
    driver.register_handler("explode.now", explode)
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret"),
        router=StaticRouter(routes={"explode.now": ["memory"]}),
    )
    kernel.register_driver(driver)

    mw = OpenAIMiddleware(kernel, reader_principal)
    outputs = await mw.handle_tool_calls(
        [
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "explode__now",
                "arguments": "{}",
            }
        ]
    )
    payload = json.loads(outputs[0]["output"])
    assert payload["error"] is True
    assert "Driver error" in payload["message"]


# ── OpenAI: argument parsing edge cases ───────────────────────────────────────


def test_openai_parse_pre_parsed_dict_arguments() -> None:
    """Some clients pre-parse arguments; the adapter accepts dict input too."""
    req = openai_mod.tool_call_to_request(
        {
            "type": "function_call",
            "call_id": "fc_1",
            "name": "billing__list_invoices",
            "arguments": {"customer_id": "c-1"},
        }
    )
    assert req.capability_id == "billing.list_invoices"


def test_openai_parse_arguments_array_raises() -> None:
    """A JSON array (not object) in arguments is a contract violation."""
    with pytest.raises(AdapterParseError, match="must decode to a JSON object"):
        openai_mod.tool_call_to_request(
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": "[1, 2, 3]",
            }
        )


def test_openai_parse_arguments_wrong_type_raises() -> None:
    """Argument values that are neither string nor dict are rejected."""
    with pytest.raises(AdapterParseError, match="must be a JSON string or dict"):
        openai_mod.tool_call_to_request(
            {
                "type": "function_call",
                "call_id": "fc_1",
                "name": "billing__list_invoices",
                "arguments": 42,
            }
        )


def test_openai_empty_arguments_string_treated_as_empty_dict() -> None:
    req = openai_mod.tool_call_to_request(
        {
            "type": "function_call",
            "call_id": "fc_1",
            "name": "billing__list_invoices",
            "arguments": "",
        }
    )
    assert req.capability_id == "billing.list_invoices"


def test_openai_strict_with_chat_completions_format() -> None:
    """Strict flag lands inside the nested function for Chat-Completions shape."""
    cap = Capability(
        capability_id="x.y",
        name="X",
        description="d",
        safety_class=SafetyClass.READ,
        parameters_model=_InvoiceArgs,
        tool_hints=ToolHints(strict=True),
    )
    tool = openai_mod.capabilities_to_tools([cap], format="chat_completions")[0]
    assert tool["function"]["strict"] is True
    assert tool["function"]["parameters"]["additionalProperties"] is False


# ── Anthropic: edge cases ─────────────────────────────────────────────────────


def test_anthropic_tool_use_to_request_treats_none_input_as_empty() -> None:
    """Anthropic may emit ``input: null`` for zero-argument tools."""
    req = anthropic_mod.tool_use_to_request(
        {"type": "tool_use", "id": "x", "name": "billing.summarize_spend", "input": None}
    )
    assert req.capability_id == "billing.summarize_spend"


@pytest.mark.asyncio
async def test_anthropic_handle_tool_uses_parse_error_surfaces_as_error_block(
    kernel: Kernel, reader_principal: Principal
) -> None:
    """A malformed tool_use block produces an is_error result, not an exception."""
    mw = AnthropicMiddleware(kernel, reader_principal)
    results = await mw.handle_tool_uses(
        [
            # name field is missing — tool_use_to_request raises ValueError.
            {"type": "tool_use", "id": "toolu_bad", "input": {}},
        ]
    )
    assert len(results) == 1
    assert results[0]["is_error"] is True
    payload = json.loads(results[0]["content"][0]["text"])
    assert "missing a 'name'" in payload["message"]


def test_frame_to_payload_shape(kernel: Kernel) -> None:
    """frame_to_payload returns the canonical JSON shape both adapters share."""
    import datetime

    from agent_kernel.models import Frame, Handle

    handle = Handle(
        handle_id="h-1",
        capability_id="x.y",
        created_at=datetime.datetime.now(tz=datetime.timezone.utc),
        expires_at=datetime.datetime.now(tz=datetime.timezone.utc),
        total_rows=42,
    )
    frame = Frame(
        action_id="a-1",
        capability_id="x.y",
        response_mode="summary",
        facts=["one fact"],
        table_preview=[{"a": 1}],
        warnings=["careful"],
        handle=handle,
    )
    payload = frame_to_payload(frame)
    assert payload == {
        "action_id": "a-1",
        "capability_id": "x.y",
        "response_mode": "summary",
        "facts": ["one fact"],
        "table_preview": [{"a": 1}],
        "warnings": ["careful"],
        "handle": {"handle_id": "h-1", "total_rows": 42},
    }
