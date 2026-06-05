"""Shared plumbing for LLM tool-format adapters.

This module is private. Stable adapter API is exported from
:mod:`weaver_kernel.adapters` (and re-exported from :mod:`weaver_kernel`).

Both :class:`~weaver_kernel.adapters.openai.OpenAIMiddleware` and
:class:`~weaver_kernel.adapters.anthropic.AnthropicMiddleware` build on top of
:class:`BaseToolMiddleware`, which owns:

- hook registration and dispatch (sync or async callables)
- the request → grant → invoke → format flow
- error-as-result conversion for kernel-side failures
- the canonical :class:`Frame` → JSON payload shape
- pydantic-driven schema generation and argument validation
- the dot-notation ↔ ``namespace__function`` round-trip used by OpenAI
"""

from __future__ import annotations

import copy
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from pydantic import ValidationError

from ..errors import (
    AdapterParseError,
    AgentKernelError,
    CapabilityNotFound,
    DriverError,
    PolicyDenied,
)
from ..models import (
    Capability,
    CapabilityRequest,
    Frame,
    Principal,
    ResponseMode,
)

if TYPE_CHECKING:
    from ..kernel import Kernel

logger = logging.getLogger(__name__)

# Sentinel returned to vendors when a tool call is aborted by a hook.
_ABORT_PREFIX = "Aborted by pre-invocation hook"

# Used to escape dots in capability IDs for vendors that reject "." in tool names.
_NAMESPACE_SEP = "__"


# ── Event objects ─────────────────────────────────────────────────────────────


@dataclass(slots=True)
class ToolCallEvent:
    """Event delivered to ``intercept_tool_call`` hooks before kernel invocation.

    Hooks may mutate :attr:`args` to override arguments, set
    :attr:`justification` to inject a justification (required for WRITE and
    DESTRUCTIVE capabilities), or set :attr:`aborted` to skip the call. A
    skipped call still produces a tool-result for the LLM — the
    :attr:`abort_reason` is included.
    """

    capability_id: str
    args: dict[str, Any]
    principal_id: str
    vendor: Literal["openai", "anthropic"]
    call_id: str
    justification: str = ""
    aborted: bool = False
    abort_reason: str = ""


@dataclass(slots=True)
class ToolResultEvent:
    """Event delivered to ``intercept_tool_result`` hooks after kernel invocation.

    Exactly one of :attr:`frame` or :attr:`error` is non-``None``. Hooks may
    replace :attr:`frame` (e.g. to apply caching transformations) or override
    :attr:`error` (e.g. to redact internal detail before reaching the LLM).
    """

    capability_id: str
    principal_id: str
    vendor: Literal["openai", "anthropic"]
    call_id: str
    frame: Frame | None = None
    error: str | None = None


ToolCallHook = Callable[[ToolCallEvent], Any]
"""Pre-invocation hook. May return ``None`` or an awaitable."""

ToolResultHook = Callable[[ToolResultEvent], Any]
"""Post-invocation hook. May return ``None`` or an awaitable."""


# ── Schema helpers ────────────────────────────────────────────────────────────


def build_input_schema(capability: Capability) -> dict[str, Any]:
    """Derive a JSON Schema for the capability's input arguments.

    Resolution order:

    1. :attr:`Capability.parameters_model` — pydantic ``model_json_schema()``.
    2. :attr:`Capability.parameters_schema` — used verbatim.
    3. Fallback: permissive ``{"type": "object", "additionalProperties": true}``.

    Note: ``allowed_fields`` is an output-redaction control and is intentionally
    ignored here.
    """
    if capability.parameters_model is not None:
        # pydantic 2's mode="validation" mirrors what the model accepts as input.
        return capability.parameters_model.model_json_schema(mode="validation")
    if capability.parameters_schema is not None:
        # Deep-copy so downstream mutation of nested objects (e.g. tweaking
        # ``properties[...]["type"]``) does not leak into the registry.
        return copy.deepcopy(capability.parameters_schema)
    return {"type": "object", "additionalProperties": True}


def normalize_for_openai_strict(schema: dict[str, Any]) -> dict[str, Any]:
    """Best-effort normalisation of *schema* for OpenAI strict mode.

    OpenAI ``strict: true`` requires every object schema to:

    - list every property in ``required``
    - set ``additionalProperties: false``

    This walker enforces both, recursively. It does not flatten ``$ref`` /
    ``$defs`` (OpenAI's strict mode accepts those). Returns a deep-copied
    schema so the caller's input is untouched.
    """
    result = _normalize_strict(schema)
    # ``_normalize_strict`` returns ``Any`` because it handles three node
    # shapes (dict, list, scalar); at this top-level entry the input is a
    # dict so the result is too.
    assert isinstance(result, dict)
    return result


def _normalize_strict(node: Any) -> Any:
    if isinstance(node, dict):
        # Recurse first so nested objects pick up the same treatment.
        out: dict[str, Any] = {k: _normalize_strict(v) for k, v in node.items()}
        if out.get("type") == "object":
            properties = out.get("properties")
            if isinstance(properties, dict):
                out["required"] = list(properties.keys())
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [_normalize_strict(v) for v in node]
    return node


def validate_input(capability: Capability, args: dict[str, Any]) -> dict[str, Any]:
    """Validate *args* against the capability's input model, if one is set.

    Returns the validated/coerced dict (pydantic may coerce types such as
    string → int per the model's declared types). When the capability has no
    :attr:`parameters_model`, returns *args* unchanged — raw schemas are not
    validated (use a model if validation matters).

    Raises:
        ValidationError: If pydantic rejects the arguments. Callers in this
            module catch this and surface the failure as a tool-result error.
    """
    if capability.parameters_model is None:
        return args
    model = capability.parameters_model.model_validate(args)
    # ``mode="python"`` keeps nested model instances as dicts the kernel/driver
    # already understand; ``by_alias=True`` is unnecessary here because the
    # driver consumes the original field names.
    return model.model_dump(mode="python")


# ── Namespace helpers ─────────────────────────────────────────────────────────


def make_namespace_safe_name(capability_id: str) -> str:
    """Convert a dotted capability_id into a vendor-safe identifier.

    ``billing.list_invoices`` → ``billing__list_invoices``. The ``__`` separator
    is reserved: capability IDs that already contain ``__`` cannot be
    round-tripped unambiguously (``"a__b"`` and ``"a.b"`` would both map to
    ``"a__b"``), so they are rejected at adapter-emit time rather than
    silently producing colliding OpenAI tool names.

    Raises:
        AdapterParseError: If *capability_id* contains the reserved ``__``
            separator. Single underscores are fine (``"list_invoices_v2"``
            round-trips cleanly).
    """
    if _NAMESPACE_SEP in capability_id:
        raise AdapterParseError(
            f"Capability ID '{capability_id}' contains the reserved namespace "
            f"separator '{_NAMESPACE_SEP}'. The OpenAI adapter would map it to "
            f"a tool name that collides with dotted capability IDs (e.g. "
            f"'a__b' and 'a.b' both produce 'a__b'). Rename the capability or "
            f"strip the double underscore."
        )
    return capability_id.replace(".", _NAMESPACE_SEP)


def restore_namespace(safe_name: str) -> str:
    """Inverse of :func:`make_namespace_safe_name`.

    ``billing__list_invoices`` → ``billing.list_invoices``.
    """
    return safe_name.replace(_NAMESPACE_SEP, ".")


# ── Payload helpers ───────────────────────────────────────────────────────────


def frame_to_payload(frame: Frame) -> dict[str, Any]:
    """Canonical JSON-serialisable shape for a kernel :class:`Frame`.

    Used by both OpenAI and Anthropic adapters as the tool-result body. The
    shape is deterministic so LLM prompt caches remain stable.
    """
    handle: dict[str, Any] | None = None
    if frame.handle is not None:
        handle = {
            "handle_id": frame.handle.handle_id,
            "total_rows": frame.handle.total_rows,
        }
    return {
        "action_id": frame.action_id,
        "capability_id": frame.capability_id,
        "response_mode": frame.response_mode,
        "facts": list(frame.facts),
        "table_preview": list(frame.table_preview),
        "warnings": list(frame.warnings),
        "handle": handle,
    }


def error_to_payload(*, capability_id: str, error: str) -> dict[str, Any]:
    """Canonical JSON-serialisable shape for a tool-result error."""
    return {
        "error": True,
        "capability_id": capability_id,
        "message": error,
    }


# ── Middleware base ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class PreparedCall:
    """A parsed tool call ready for dispatch through the kernel pipeline.

    Adapters parse vendor-specific shapes into this neutral form before
    handing them to :meth:`BaseToolMiddleware._dispatch_one`.
    """

    call_id: str
    capability_id: str
    args: dict[str, Any]


class BaseToolMiddleware:
    """Shared base class for vendor-specific tool middleware.

    Subclasses implement only the vendor-specific shape adapters
    (``capabilities_to_tools``, ``handle_*``); the request/grant/invoke flow,
    hook dispatch, and error handling live here.
    """

    vendor: ClassVar[Literal["openai", "anthropic"]]

    def __init__(
        self,
        kernel: Kernel,
        principal: Principal,
        *,
        response_mode: ResponseMode = "summary",
    ) -> None:
        self._kernel = kernel
        self._principal = principal
        self._response_mode: ResponseMode = response_mode
        self._pre_hooks: list[ToolCallHook] = []
        self._post_hooks: list[ToolResultHook] = []

    # ── Hooks ──────────────────────────────────────────────────────────────

    def intercept_tool_call(self, callback: ToolCallHook) -> None:
        """Register a pre-invocation hook.

        Hooks are dispatched in registration order. Sync and async callables
        are both supported; an awaitable return value is awaited.
        """
        self._pre_hooks.append(callback)

    def intercept_tool_result(self, callback: ToolResultHook) -> None:
        """Register a post-invocation hook.

        Hooks are dispatched in registration order. Sync and async callables
        are both supported; an awaitable return value is awaited.
        """
        self._post_hooks.append(callback)

    # ── Internal — capability lookup ───────────────────────────────────────

    def _list_capabilities(self) -> list[Capability]:
        return self._kernel.list_capabilities()

    def _get_capability(self, capability_id: str) -> Capability | None:
        for cap in self._kernel.list_capabilities():
            if cap.capability_id == capability_id:
                return cap
        return None

    # ── Internal — dispatch ────────────────────────────────────────────────

    async def _dispatch_one(
        self,
        prepared: PreparedCall,
        *,
        batch_justification: str,
    ) -> ToolResultEvent:
        """Run a single prepared call through hooks → kernel → hooks."""
        principal_id = self._principal.principal_id
        per_call_justification = ""
        args = dict(prepared.args)
        if "_justification" in args:
            value = args.pop("_justification")
            per_call_justification = str(value) if value is not None else ""

        event = ToolCallEvent(
            capability_id=prepared.capability_id,
            args=args,
            principal_id=principal_id,
            vendor=self.vendor,
            call_id=prepared.call_id,
            justification=per_call_justification or batch_justification,
        )

        result_event = ToolResultEvent(
            capability_id=prepared.capability_id,
            principal_id=principal_id,
            vendor=self.vendor,
            call_id=prepared.call_id,
        )

        try:
            await self._fire_pre_hooks(event)
        except Exception as exc:  # noqa: BLE001 — hook errors become tool errors
            result_event.error = f"Pre-invocation hook raised: {exc}"
            await self._fire_post_hooks(result_event)
            return result_event

        if event.aborted:
            reason = event.abort_reason or "no reason provided"
            result_event.error = f"{_ABORT_PREFIX}: {reason}"
            await self._fire_post_hooks(result_event)
            return result_event

        result_event.frame, result_event.error = await self._invoke_capability(event)
        await self._fire_post_hooks(result_event)
        return result_event

    async def _invoke_capability(self, event: ToolCallEvent) -> tuple[Frame | None, str | None]:
        """Run grant + invoke, mapping kernel exceptions to tool-result errors."""
        capability = self._get_capability(event.capability_id)
        if capability is None:
            return None, (f"Capability '{event.capability_id}' is not registered in this kernel.")

        # Validate arguments against the capability's schema (if any).
        try:
            validated_args = validate_input(capability, event.args)
        except ValidationError as exc:
            return None, f"Argument validation failed: {exc}"

        request = CapabilityRequest(
            capability_id=event.capability_id,
            goal=f"adapter:{self.vendor}",
            constraints={},
        )

        try:
            grant = self._kernel.grant_capability(
                request, self._principal, justification=event.justification
            )
        except PolicyDenied as exc:
            return None, f"Policy denied: {exc}"
        except CapabilityNotFound as exc:
            # Race between list_capabilities and grant; surface cleanly.
            return None, f"Capability not found: {exc}"

        try:
            frame = await self._kernel.invoke(
                grant.token,
                principal=self._principal,
                args=validated_args,
                response_mode=self._response_mode,
            )
        except DriverError as exc:
            return None, f"Driver error: {exc}"
        except AgentKernelError as exc:
            return None, f"Kernel error: {exc}"
        return frame, None

    # ── Hook dispatch ──────────────────────────────────────────────────────

    async def _fire_pre_hooks(self, event: ToolCallEvent) -> None:
        for hook in self._pre_hooks:
            await self._await_if_needed(hook(event))

    async def _fire_post_hooks(self, event: ToolResultEvent) -> None:
        for hook in self._post_hooks:
            # Hook exceptions during post-processing are logged but never
            # crash the surrounding tool-call batch.
            try:
                await self._await_if_needed(hook(event))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "post_hook_failed",
                    extra={
                        "capability_id": event.capability_id,
                        "call_id": event.call_id,
                        "vendor": self.vendor,
                        "error": str(exc),
                    },
                )

    @staticmethod
    async def _await_if_needed(value: Any) -> None:
        if inspect.isawaitable(value):
            await value


# Public re-exports so ``from weaver_kernel.adapters import X`` resolves
# cleanly even for internals subclasses lean on.
__all__ = [
    "BaseToolMiddleware",
    "PreparedCall",
    "ToolCallEvent",
    "ToolCallHook",
    "ToolResultEvent",
    "ToolResultHook",
    "build_input_schema",
    "error_to_payload",
    "frame_to_payload",
    "make_namespace_safe_name",
    "normalize_for_openai_strict",
    "restore_namespace",
    "validate_input",
]
