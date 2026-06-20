"""weaver-spec conformance adapter (issue #225).

Maps the kernel's runtime objects (:class:`~weaver_kernel.models.Frame`,
:class:`~weaver_kernel.trace.ActionTrace`,
:class:`~weaver_kernel.tokens.CapabilityToken`) onto the published
``weaver-contracts`` dataclasses, so CI can assert the kernel emits
spec-conformant payloads instead of echoing a placeholder.

``weaver-contracts`` is an optional dependency (the ``conformance`` extra):
``import weaver_kernel`` never requires it. Each adapter imports it lazily and
raises a clear :class:`ImportError` with an install hint when it is absent,
mirroring the optional-extra seam used by the MCP and OTel integrations.

The adapters intentionally translate vocabulary where the contract and the
kernel differ (notably trace ``event_type``); the mapping policy lives here so
contract gaps surface in one place and can be filed upstream rather than by
bending kernel types.
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .models import ActionTrace, Frame
    from .tokens import CapabilityToken

# Kernel trace event_type -> weaver-contracts TraceEvent.event_type. The
# contract speaks a richer lifecycle vocabulary; these are the documented
# equivalences for the three audited kernel events.
_EVENT_TYPE_MAP = {
    "invoke": "capability_executed",
    "expand": "handle_resolved",
    "deny": "capability_denied",
}


def _require_contracts() -> Any:
    """Import and return the ``weaver_contracts`` package or raise a clear error."""
    try:
        import weaver_contracts
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via extra absence
        raise ImportError(
            "Conformance mapping requires the optional dependency "
            "'weaver-contracts'. Install it with: pip install 'weaver-kernel[conformance]'"
        ) from exc
    return weaver_contracts


def contract_version() -> str:
    """Return the installed ``weaver-contracts`` CONTRACT_VERSION string.

    Returns:
        The semantic version of the contract package the kernel is mapped to.
    """
    return str(_require_contracts().CONTRACT_VERSION)


def frame_to_contract(frame: Frame, *, created_at: datetime.datetime | None = None) -> Any:
    """Map a kernel :class:`Frame` to a ``weaver_contracts.Frame``.

    Args:
        frame: The firewalled frame produced at the kernel boundary.
        created_at: Timestamp for the contract frame. Defaults to the current
            UTC time, since the kernel ``Frame`` carries no creation timestamp.

    Returns:
        A validated ``weaver_contracts.Frame`` (its ``__post_init__`` enforces
        the contract invariants, e.g. a non-empty summary).
    """
    wc = _require_contracts()
    summary = "; ".join(frame.facts) if frame.facts else f"{frame.response_mode} result"
    handle_refs = [frame.handle.handle_id] if frame.handle is not None else []
    return wc.Frame(
        frame_id=frame.action_id,
        capability_id=frame.capability_id,
        summary=summary,
        created_at=created_at or datetime.datetime.now(tz=datetime.timezone.utc),
        structured_data={"table_preview": frame.table_preview} if frame.table_preview else None,
        handle_refs=handle_refs,
        redaction_notes="; ".join(frame.warnings) if frame.warnings else None,
        metadata={"response_mode": frame.response_mode, "is_final": frame.is_final},
    )


def trace_to_contract(trace: ActionTrace) -> Any:
    """Map a kernel :class:`ActionTrace` to a ``weaver_contracts.TraceEvent``.

    Args:
        trace: The audit record for an invoke/expand/deny event.

    Returns:
        A validated ``weaver_contracts.TraceEvent`` with kernel-specific detail
        (driver, sensitivity, reason code) carried in ``metadata``.
    """
    wc = _require_contracts()
    is_deny = trace.event_type == "deny"
    outcome = "failure" if (is_deny or trace.error is not None) else "success"
    return wc.TraceEvent(
        event_id=trace.action_id,
        event_type=_EVENT_TYPE_MAP[trace.event_type],
        timestamp=trace.invoked_at,
        capability_id=trace.capability_id,
        principal=trace.principal_id,
        frame_id=None if is_deny else trace.action_id,
        handle_id=trace.handle_id,
        outcome=outcome,
        error_message=trace.error,
        metadata={
            "reason_code": trace.reason_code,
            "sensitivity": str(trace.sensitivity.value),
            "driver_id": trace.driver_id,
            "response_mode": trace.response_mode,
        },
    )


def token_to_contract(token: CapabilityToken) -> Any:
    """Map a kernel :class:`CapabilityToken` to a ``weaver_contracts.CapabilityToken``.

    Args:
        token: An issued, signed capability token.

    Returns:
        A validated ``weaver_contracts.CapabilityToken`` whose ``scope`` is the
        single capability the kernel token authorises.
    """
    wc = _require_contracts()
    return wc.CapabilityToken(
        token_id=token.token_id,
        principal=token.principal_id,
        scope=[token.capability_id],
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        single_use=False,
        issuer=None,
        metadata={"audit_id": token.audit_id, "constraints": token.constraints},
    )


__all__ = [
    "contract_version",
    "frame_to_contract",
    "trace_to_contract",
    "token_to_contract",
]
