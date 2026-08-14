"""Ordered rule chain shared by default policy decisions and explanations."""

from __future__ import annotations

from collections.abc import Callable

from .default_policy_access_rules import (
    check_memory,
    check_safety_class,
    check_secrets,
    check_tenant_sensitivity,
)
from .default_policy_limit_rules import apply_row_cap, check_rate_limit
from .default_policy_rule_types import (
    MAX_ROWS_SERVICE,
    MAX_ROWS_USER,
    MIN_JUSTIFICATION,
    RuleChainResult,
    RuleContext,
    RuleFailure,
)
from .enums import SafetyClass
from .models import Capability, CapabilityRequest, Principal
from .rate_limit import RateLimiter

RuleCheck = Callable[[RuleContext], list[RuleFailure]]

# Canonical order is defined once here. Both evaluate() and explain() traverse
# exactly this sequence; their only differences are short-circuit/collect-all
# and stateful/read-only rate-limit modes.
_DEFAULT_RULES: tuple[RuleCheck, ...] = (
    check_safety_class,
    check_tenant_sensitivity,
    check_secrets,
    check_memory,
    apply_row_cap,
    check_rate_limit,
)


class DefaultPolicyRuleChain:
    """Single ordered definition of the built-in default policy rules."""

    def __init__(
        self,
        *,
        rate_limits: dict[SafetyClass, tuple[int, float]],
        limiter: RateLimiter,
    ) -> None:
        self._rate_limits = rate_limits
        self._limiter = limiter

    def run(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
        collect_all: bool,
        read_only: bool,
    ) -> RuleChainResult:
        """Traverse the canonical rules in decision or explanation mode.

        Args:
            request: Capability request being checked.
            capability: Target capability.
            principal: Requesting principal.
            justification: Caller-supplied justification.
            collect_all: Collect every failed condition instead of stopping at
                the first one.
            read_only: Avoid policy-state mutation, including rate-window
                creation, pruning, and usage recording.

        Returns:
            Constraints, failures, and non-terminal trace steps produced by the
            common rule traversal.
        """
        ctx = RuleContext(
            request=request,
            capability=capability,
            principal=principal,
            justification=justification,
            constraints=dict(request.constraints),
            rate_limits=self._rate_limits,
            limiter=self._limiter,
            read_only=read_only,
        )
        failures: list[RuleFailure] = []
        for rule in _DEFAULT_RULES:
            rule_failures = rule(ctx)
            if rule_failures:
                failures.extend(rule_failures)
                if not collect_all:
                    failures = failures[:1]
                    break

        return RuleChainResult(
            constraints=ctx.constraints,
            failures=failures,
            trace_steps=ctx.trace_steps,
        )


__all__ = [
    "DefaultPolicyRuleChain",
    "MAX_ROWS_SERVICE",
    "MAX_ROWS_USER",
    "MIN_JUSTIFICATION",
    "RuleChainResult",
    "RuleFailure",
]
