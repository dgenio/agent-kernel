"""Internal helper for :meth:`Kernel.grant_capability`.

Split out of :mod:`kernel` to keep the public API module ≤ 300 lines
(AGENTS.md), the same way :mod:`._invoke` and :mod:`._dry_run` were.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from ..errors import PolicyDenied
from ..models import CapabilityGrant
from ._audit import record_denial_trace

if TYPE_CHECKING:  # pragma: no cover
    from ..models import Capability, CapabilityRequest, Principal
    from ..policy import PolicyEngine
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")


def _resolve_ttl(
    policy: PolicyEngine, capability: Capability, principal: Principal, ttl_s: float | None
) -> float | None:
    """Resolve the effective grant TTL via the policy's optional ``resolve_ttl``.

    ``resolve_ttl(capability, principal, ttl_s) -> float | None`` is
    deliberately *not* part of the :class:`~weaver_kernel.PolicyEngine`
    Protocol (adding a required method there would break every third-party
    implementation, the same reasoning that split
    :class:`~weaver_kernel.ExplainingPolicyEngine` off in 0.7.0). Engines
    that don't implement it simply pass *ttl_s* through unchanged — TTL
    validation is opt-in policy behavior, not a kernel-mandated one (#203).

    Raises:
        PolicyDenied: If the policy engine's ``resolve_ttl`` rejects *ttl_s*
            (e.g. it is non-positive, or exceeds a configured
            per-safety-class maximum).
    """
    resolve_ttl = getattr(policy, "resolve_ttl", None)
    if resolve_ttl is None:
        return ttl_s
    result: float | None = resolve_ttl(capability, principal, ttl_s)
    return result


def perform_grant(
    kernel: Kernel,
    request: CapabilityRequest,
    principal: Principal,
    *,
    justification: str,
    ttl_s: float | None = None,
) -> CapabilityGrant:
    """Evaluate the policy and, if approved, issue a signed token.

    On a :class:`~weaver_kernel.PolicyDenied` rejection — from either the
    policy engine's ``evaluate()`` or an over-maximum *ttl_s* — a ``"deny"``
    audit record (carrying the stable reason code) is written to the trace
    store (best-effort) before the exception propagates, so the audit trail
    answers "who was refused what, and why" (#175). A trace-store write
    failure is logged but never masks the denial. Denials are also counted
    in :attr:`~weaver_kernel.Kernel.stats`.

    Args:
        kernel: The orchestrating :class:`~weaver_kernel.Kernel`.
        request: The capability request to grant.
        principal: The principal requesting the grant.
        justification: Free-text justification for the grant.
        ttl_s: Requested token lifetime in seconds. ``None`` (the default)
            uses the token provider's own default — unchanged behavior. A
            policy engine may deny (never silently clamp) an excessive value
            via an optional ``resolve_ttl`` method (#203).

    Returns:
        A :class:`~weaver_kernel.CapabilityGrant` carrying the signed token.
    """
    capability = kernel._registry.get(request.capability_id)
    try:
        decision = kernel._policy.evaluate(
            request, capability, principal, justification=justification
        )
        effective_ttl_s = _resolve_ttl(kernel._policy, capability, principal, ttl_s)
    except PolicyDenied as exc:
        kernel._stats.on_denial(exc.reason_code)
        # The denial is authoritative and already fails closed (no token is
        # issued). Recording its audit trace is best-effort: a trace-store
        # write failure must never mask the PolicyDenied the caller expects.
        try:
            record_denial_trace(
                capability_id=request.capability_id,
                principal_id=principal.principal_id,
                reason_code=exc.reason_code,
                message=str(exc),
                trace_store=kernel._trace_store,
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
    issue_kwargs: dict[str, Any] = {"constraints": decision.constraints, "audit_id": audit_id}
    if effective_ttl_s is not None:
        issue_kwargs["ttl_seconds"] = effective_ttl_s
    token = kernel._token_provider.issue(
        capability.capability_id,
        principal.principal_id,
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
