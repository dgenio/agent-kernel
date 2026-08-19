"""Grant-capability orchestration and per-grant TTL enforcement (#203).

Extracted from :mod:`weaver_kernel.kernel` to keep the public API module within
the AGENTS.md 300-line budget (mirrors the ``_invoke``/``_dry_run`` split). The
per-grant TTL is validated *before* policy evaluation so a doomed grant never
consumes rate-limit quota, then threaded into token issuance.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from ..errors import PolicyDenied
from ..models import Capability, CapabilityGrant, CapabilityRequest, Principal
from ..policy import PolicyEngine
from ..policy_reasons import DenialReason
from ..policy_ttl import resolve_max_ttl_s
from ._audit import record_denial_trace

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")


def _validate_ttl(policy: PolicyEngine, capability: Capability, ttl_s: int | None) -> None:
    """Deny a per-grant TTL that is non-positive or over the policy maximum (#203).

    Args:
        policy: The active policy engine; consulted (duck-typed) for
            ``max_ttl_s`` so third-party engines without it impose no maximum.
        capability: The capability being granted.
        ttl_s: The requested TTL in seconds, or ``None`` for the provider default.

    Raises:
        PolicyDenied: If *ttl_s* is non-positive (``INVALID_CONSTRAINT``) or
            exceeds the policy maximum (``TTL_EXCEEDED``). Never clamps silently.
    """
    if ttl_s is None:
        return
    if ttl_s <= 0:
        raise PolicyDenied(
            f"Requested ttl_s must be a positive number of seconds, got {ttl_s}.",
            reason_code=DenialReason.INVALID_CONSTRAINT,
        )
    max_ttl = resolve_max_ttl_s(getattr(policy, "max_ttl_s", None), capability)
    if max_ttl is not None and ttl_s > max_ttl:
        raise PolicyDenied(
            f"Requested ttl_s={ttl_s} exceeds the maximum of {max_ttl}s for "
            f"{capability.safety_class.value} capabilities.",
            reason_code=DenialReason.TTL_EXCEEDED,
        )


def perform_grant(
    kernel: Kernel,
    request: CapabilityRequest,
    principal: Principal,
    *,
    justification: str,
    ttl_s: int | None,
) -> CapabilityGrant:
    """Evaluate the policy and, if approved, issue a signed token.

    On a :class:`~weaver_kernel.PolicyDenied` rejection — including a TTL denial
    raised before evaluation — a ``"deny"`` audit record (carrying the stable
    reason code) is written to the trace store (best-effort) before the exception
    propagates. A trace-store write failure is logged but never masks the denial.

    Args:
        kernel: The orchestrating :class:`Kernel` (private accessors used for the
            registry, policy, token provider, trace store, and stats).
        request: The capability request being granted.
        principal: The principal the grant is issued to.
        justification: Free-text justification forwarded to the policy engine.
        ttl_s: Optional per-grant token TTL in seconds; ``None`` uses the token
            provider's default.

    Returns:
        The issued :class:`~weaver_kernel.models.CapabilityGrant`.
    """
    capability = kernel._registry.get(request.capability_id)
    try:
        _validate_ttl(kernel._policy, capability, ttl_s)
        decision = kernel._policy.evaluate(
            request, capability, principal, justification=justification
        )
    except PolicyDenied as exc:
        kernel._stats.on_denial(exc.reason_code)
        # The denial is authoritative and already fails closed (no token is
        # issued). Recording its audit trace is best-effort: a trace-store write
        # failure must never mask the PolicyDenied the caller expects.
        try:
            record_denial_trace(
                capability_id=request.capability_id,
                principal_id=principal.principal_id,
                reason_code=exc.reason_code,
                message=str(exc),
                trace_store=kernel._traces,
            )
        except Exception:
            logger.warning(
                "deny_trace_record_failed",
                extra={
                    "capability_id": request.capability_id,
                    "principal_id": principal.principal_id,
                    "reason_code": exc.reason_code,
                },
                exc_info=True,
            )
        raise
    audit_id = str(uuid.uuid4())
    issue_kwargs = {} if ttl_s is None else {"ttl_seconds": ttl_s}
    token = kernel._token_provider.issue(
        capability.capability_id,
        principal.principal_id,
        constraints=decision.constraints,
        audit_id=audit_id,
        **issue_kwargs,
    )
    logger.info(
        "grant_capability",
        extra={
            "principal_id": principal.principal_id,
            "capability_id": capability.capability_id,
            "safety_class": capability.safety_class.value,
            "audit_id": audit_id,
            "token_id": token.token_id,
            "ttl_s": ttl_s,
        },
    )
    kernel._stats.on_grant()
    return CapabilityGrant(
        request=request,
        principal=principal,
        decision=decision,
        token=token,
        audit_id=audit_id,
    )


__all__ = ["perform_grant"]
