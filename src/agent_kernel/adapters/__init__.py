"""LLM tool-format adapters and middleware.

The adapter layer translates between :class:`~agent_kernel.Capability` objects
and vendor-specific tool shapes (OpenAI Responses / Chat Completions,
Anthropic Messages) without depending on the vendor SDKs at runtime. The
middleware classes also route a vendor's tool-call objects through the full
kernel pipeline (grant → invoke → firewall → trace), returning vendor-shaped
tool-result objects.

Two middleware classes share a common base (:class:`BaseToolMiddleware`) which
owns hook registration, dispatch, and error-as-result conversion.
"""

from __future__ import annotations

from ._base import (
    BaseToolMiddleware,
    ToolCallEvent,
    ToolCallHook,
    ToolResultEvent,
    ToolResultHook,
)
from .anthropic import AnthropicMiddleware
from .openai import OpenAIMiddleware, OpenAIToolFormat

__all__ = [
    "AnthropicMiddleware",
    "BaseToolMiddleware",
    "OpenAIMiddleware",
    "OpenAIToolFormat",
    "ToolCallEvent",
    "ToolCallHook",
    "ToolResultEvent",
    "ToolResultHook",
]
