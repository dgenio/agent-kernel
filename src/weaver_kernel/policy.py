"""Policy engine: role-based access control with confused-deputy prevention."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Protocol

from .default_policy_rules import DefaultPolicyRuleChain
from .enums import SafetyClass
from .errors import AgentKernelError, PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    DenialExplanation,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
)
from .policy_reasons import AllowReason
from .rate_limit import DEFAULT_RATE_LIMITS, SERVICE_RATE_MULTIPLIER, RateLimiter

logger = logging.getLogger(__name__)

# Backwards-compatible aliases — these used to be defined here. New code
# should import the names without the leading underscore from ``rate_limit``.
_DEFAULT_RATE_LIMITS = DEFAULT_RATE_LIMITS
_SERVICE_RATE_MULTIPLIER = SERVICE_RATE_MULTIPLIER


class PolicyEngine(Protocol):
    """Interface for a policy engine.

    Implementations need only provide :meth:`evaluate`. To enable structured
    denial explanations via :meth:`Kernel.explain_denial`, additionally
    implement :meth:`ExplainingPolicyEngine.explain` — engines that satisfy
    only this base protocol cause :meth:`Kernel.explain_denial` to raise
    :class:`AgentKernelError`.
    """

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate whether *principal* may perform *request* on *capability*.

        Args:
            request: The capability request being evaluated.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            A :class:`PolicyDecision` (allowed or denied with reason).
        """
        ...


class ExplainingPolicyEngine(PolicyEngine, Protocol):
    """Policy engine that can produce structured denial explanations.

    :meth:`Kernel.explain_denial` requires this richer contract; downstream
    engines that only implement :class:`PolicyEngine` keep working for
    :meth:`Kernel.grant_capability` and :meth:`Kernel.invoke` but cannot
    answer :meth:`Kernel.explain_denial`.

    Both built-in engines (:class:`DefaultPolicyEngine` and
    :class:`weaver_kernel.DeclarativePolicyEngine`) satisfy this protocol.
    """

    def explain(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> DenialExplanation:
        """Explain why *principal*'s *request* would be denied (or allowed).

        Unlike :meth:`evaluate`, this method never raises — it collects all
        failing conditions and returns a structured :class:`DenialExplanation`.

        Args:
            request: The capability request to explain.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            A :class:`DenialExplanation` with ``denied=False`` if the request
            would succeed.
        """
        ...


class DefaultPolicyEngine:
    """Rule-based policy engine implementing the default access control policy.

    Rules (evaluated in order):

    1. **READ** — allowed (subject to sensitivity and row-cap rules below).
    2. **WRITE** — requires:
       - ``justification`` of at least 15 characters.
       - Principal role ``"writer"`` **or** ``"admin"``.
    3. **DESTRUCTIVE** — requires principal role ``"admin"``.
    4. **PII / PCI sensitivity** — requires the ``tenant`` attribute on the
       principal.  Enforces ``allowed_fields`` unless the principal has the
       ``pii_reader`` role.
    5. **SECRETS sensitivity** — requires principal role ``"admin"`` or
       ``"secrets_reader"`` and a justification of at least 15 characters.
    6. **max_rows** — 50 for regular users; 500 for principals with the
       ``"service"`` role.
    7. **Rate limiting** — sliding-window rate limit per
       ``(principal_id, capability_id)`` pair, with defaults by safety class.
       Principals with the ``"service"`` role get 10× the default limits.
    """

    def __init__(
        self,
        *,
        rate_limits: dict[SafetyClass, tuple[int, float]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Initialise the policy engine.

        Args:
            rate_limits: Override default rate limits per safety class.
                Each value is ``(max_invocations, window_seconds)``.
                Partial overrides are merged into the defaults so that
                unspecified safety classes retain their default limits.
            clock: Monotonic clock callable for rate-limiter.
                Defaults to :func:`time.monotonic`.
        """
        limits = dict(_DEFAULT_RATE_LIMITS)
        if rate_limits is not None:
            limits.update(rate_limits)
        for sc, (count, window) in limits.items():
            if count < 1 or window <= 0:
                raise AgentKernelError(
                    f"Invalid rate limit for {sc.value}: "
                    f"limit must be >= 1 and window must be > 0, "
                    f"got limit={count}, window={window}."
                )
        self._rate_limits = limits
        self._limiter = RateLimiter(clock=clock)
        self._rule_chain = DefaultPolicyRuleChain(
            rate_limits=self._rate_limits, limiter=self._limiter
        )

    @staticmethod
    def _deny(
        reason: str,
        *,
        principal_id: str,
        capability_id: str,
        reason_code: str,
    ) -> PolicyDenied:
        """Log a policy denial at WARNING and return the exception to raise."""
        logger.warning(
            "policy_denied",
            extra={
                "principal_id": principal_id,
                "capability_id": capability_id,
                "reason": reason,
                "reason_code": reason_code,
            },
        )
        return PolicyDenied(reason, reason_code=reason_code)

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate the request against the shared default-policy rule chain.

        Decision traversal short-circuits on the first denial and may update
        transient policy state (currently the sliding-window rate limiter).
        ``explain()`` traverses this exact same chain in read-only mode.
        """
        pid = principal.principal_id
        cid = capability.capability_id
        trace = PolicyDecisionTrace(
            engine="DefaultPolicyEngine",
            capability_id=cid,
            principal_id=pid,
            intent=request.intent,
            scope_keys=sorted(request.scope.keys()),
        )
        result = self._rule_chain.run(
            request,
            capability,
            principal,
            justification=justification,
            collect_all=False,
            read_only=False,
        )
        trace.steps.extend(result.trace_steps)

        if result.failures:
            failure = result.failures[0]
            trace.steps.append(
                PolicyTraceStep(
                    name="deny",
                    outcome="denied",
                    detail=failure.detail,
                    reason_code=failure.reason_code,
                )
            )
            trace.final_outcome = "denied"
            trace.final_reason_code = failure.reason_code
            denial = self._deny(
                failure.detail,
                principal_id=pid,
                capability_id=cid,
                reason_code=failure.reason_code,
            )
            if failure.cause is not None:
                raise denial from failure.cause
            raise denial

        reason = "Request approved by DefaultPolicyEngine."
        trace.steps.append(
            PolicyTraceStep(
                name="allow",
                outcome="allowed",
                detail=reason,
                reason_code=str(AllowReason.DEFAULT_POLICY_ALLOW),
            )
        )
        trace.final_outcome = "allowed"
        trace.final_reason_code = str(AllowReason.DEFAULT_POLICY_ALLOW)
        logger.info(
            "policy_allowed",
            extra={
                "principal_id": pid,
                "capability_id": cid,
                "reason": reason,
                "reason_code": str(AllowReason.DEFAULT_POLICY_ALLOW),
            },
        )
        return PolicyDecision(
            allowed=True,
            reason=reason,
            constraints=result.constraints,
            reason_code=str(AllowReason.DEFAULT_POLICY_ALLOW),
            trace=trace,
        )

    def explain(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> DenialExplanation:
        """Explain all failures from the same chain used by :meth:`evaluate`.

        Explanation is strictly read-only: it collects all failed conditions,
        including the current rate-limit condition, without recording usage or
        pruning/creating limiter windows.
        """
        pid = principal.principal_id
        cid = capability.capability_id
        result = self._rule_chain.run(
            request,
            capability,
            principal,
            justification=justification,
            collect_all=True,
            read_only=True,
        )
        failed = [failure.condition for failure in result.failures]
        denied = bool(failed)
        remediation = [condition.suggestion for condition in failed]

        if denied:
            first = failed[0]
            rule_name = (
                f"{capability.safety_class.value.lower()}-{first.condition.replace('_', '-')}"
            )
            narrative = (
                f"Request for '{cid}' by '{pid}' would be denied: "
                + "; ".join(condition.suggestion for condition in failed)
                + "."
            )
            primary_code = first.reason_code
        else:
            rule_name = "allowed"
            narrative = f"Request for '{cid}' by '{pid}' would be allowed by DefaultPolicyEngine."
            primary_code = None

        return DenialExplanation(
            denied=denied,
            rule_name=rule_name,
            failed_conditions=failed,
            remediation=remediation,
            narrative=narrative,
            reason_code=primary_code,
        )
