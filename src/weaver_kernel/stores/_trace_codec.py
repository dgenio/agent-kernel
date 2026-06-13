"""Encode/decode :class:`ActionTrace` ↔ the persisted, redaction-safe payload.

Encoding reuses :func:`~weaver_kernel.export_action_trace`, so a persisted
record contains exactly the stable export shape (issue #94) — nothing the
in-memory trace did not already hold. Decoding is its inverse; the export-only
``status`` and ``correction`` fields are derived/ignored on the way back.
"""

from __future__ import annotations

import datetime
from typing import Any

from ..enums import SensitivityTag
from ..errors import AgentKernelError
from ..models import ActionTrace
from ..trace import export_action_trace


def encode_trace(trace: ActionTrace) -> dict[str, Any]:
    """Return the redaction-safe, JSON-serialisable payload for *trace*."""
    return export_action_trace(trace)


def decode_trace(payload: dict[str, Any]) -> ActionTrace:
    """Reconstruct an :class:`ActionTrace` from a persisted payload.

    Raises:
        AgentKernelError: If the payload is missing a required field — surfaced
            as a kernel error rather than a bare ``KeyError`` (see AGENTS.md).
    """
    try:
        return ActionTrace(
            action_id=payload["action_id"],
            capability_id=payload["capability_id"],
            principal_id=payload["principal_id"],
            token_id=payload["token_id"],
            invoked_at=datetime.datetime.fromisoformat(payload["invoked_at"]),
            args=payload["args"],
            response_mode=payload["response_mode"],
            driver_id=payload["driver_id"],
            handle_id=payload.get("handle_id"),
            error=payload.get("error"),
            result_summary=payload.get("result_summary"),
            sensitivity=SensitivityTag(payload.get("sensitivity", "NONE")),
        )
    except KeyError as exc:
        raise AgentKernelError(
            f"Persisted trace payload is missing required field {exc}."
        ) from exc
