"""Shared rule chain for :class:`~weaver_kernel.policy.DefaultPolicyEngine`.

This module owns the ordered default-policy conditions.  ``evaluate()`` and
``explain()`` deliberately traverse this same chain with different modes:
short-circuit + stateful rate limiting for decisions, collect-all + read-only
rate inspection for explanations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import SafetyClass, SensitivityTag
from .models import (
    Capability,
    CapabilityRequest,
    FailedCondition,
    PolicyTraceStep,
    Principal,
)
from .policy_reasons import DenialReason
from .rate_limit import SERVICE_RATE_MULTIPLIER, RateLimiter

MIN_JUSTIFICATION = 15
MAX_ROWS_USER = 50
MAX_ROWS_SERVICE = 500


@dataclass(slots=True)
class RuleFailure:
    """One failed default-policy condition and its decision/explanation views."""

    detail: str
    condition: FailedCondition
    reason_code: str
    cause: Exception | None = None


@dataclass(slots=True)
class RuleChainResult:
    """Result of traversing the ordered default-policy rule chain."""

    constraints: dict[str, Any]
    failures: list[RuleFailure] = field(default_factory=list)
    trace_steps: list[PolicyTraceStep] = field(default_factory=list)


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
        """Traverse the rules once in canonical order.

        Args:
            request: Capability request being checked.
            capability: Target capability.
            principal: Requesting principal.
            justification: Caller-supplied justification.
            collect_all: Collect every failure instead of stopping at the first.
            read_only: Do not mutate transient policy state such as rate windows.

        Returns:
            Constraints, failed conditions, and non-terminal trace steps.
        """
        roles = set(principal.roles)
        constraints: dict[str, Any] = dict(request.constraints)
        result = RuleChainResult(constraints=constraints)
        pid = principal.principal_id
        cid = capability.capability_id

        def add_failure(
            *,
            detail: str,
            condition: FailedCondition,
            reason_code: str,
            cause: Exception | None = None,
        ) -> bool:
            result.failures.append(
                RuleFailure(
                    detail=detail,
                    condition=condition,
                    reason_code=reason_code,
                    cause=cause,
                )
            )
            return not collect_all

        # ── Safety class checks ──────────────────────────────────────────
        if capability.safety_class == SafetyClass.WRITE:
            if not (roles & {"writer", "admin"}):
                detail = (
                    f"WRITE capabilities require the 'writer' or 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="roles",
                        required=["writer", "admin"],
                        actual=sorted(roles),
                        suggestion=f"Add 'writer' or 'admin' role to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ROLE),
                    ),
                    reason_code=str(DenialReason.MISSING_ROLE),
                ):
                    return result
            stripped_len = len(justification.strip())
            if stripped_len < MIN_JUSTIFICATION:
                detail = (
                    f"WRITE capabilities require a justification of at least "
                    f"{MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="min_justification",
                        required=MIN_JUSTIFICATION,
                        actual=stripped_len,
                        suggestion=(
                            f"Provide justification with at least {MIN_JUSTIFICATION} "
                            f"characters (currently {stripped_len})"
                        ),
                        reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                    ),
                    reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                ):
                    return result

        elif capability.safety_class == SafetyClass.DESTRUCTIVE:
            if "admin" not in roles:
                detail = (
                    f"DESTRUCTIVE capabilities require the 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="roles",
                        required=["admin"],
                        actual=sorted(roles),
                        suggestion=f"Add 'admin' role to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ROLE),
                    ),
                    reason_code=str(DenialReason.MISSING_ROLE),
                ):
                    return result
            stripped_len = len(justification.strip())
            if stripped_len < MIN_JUSTIFICATION:
                detail = (
                    f"DESTRUCTIVE capabilities require a justification of at least "
                    f"{MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="min_justification",
                        required=MIN_JUSTIFICATION,
                        actual=stripped_len,
                        suggestion=(
                            f"Provide justification with at least {MIN_JUSTIFICATION} "
                            f"characters (currently {stripped_len})"
                        ),
                        reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                    ),
                    reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                ):
                    return result

        # ── Sensitivity checks ───────────────────────────────────────────
        if capability.sensitivity in (SensitivityTag.PII, SensitivityTag.PCI):
            if "tenant" not in principal.attributes:
                detail = (
                    f"Capability '{cid}' has "
                    f"{capability.sensitivity.value} sensitivity and requires "
                    "the principal to have a 'tenant' attribute."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="tenant_attribute",
                        required="present",
                        actual="absent",
                        suggestion=f"Add 'tenant' attribute to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_TENANT_ATTRIBUTE),
                    ),
                    reason_code=str(DenialReason.MISSING_TENANT_ATTRIBUTE),
                ):
                    return result
            if capability.allowed_fields and "pii_reader" not in roles:
                constraints["allowed_fields"] = capability.allowed_fields
                result.trace_steps.append(
                    PolicyTraceStep(
                        name="sensitivity:allowed_fields",
                        outcome="constraint_applied",
                        detail=f"applied allowed_fields={capability.allowed_fields}",
                    )
                )

        if capability.sensitivity == SensitivityTag.SECRETS:
            if not (roles & {"admin", "secrets_reader"}):
                detail = (
                    f"SECRETS capabilities require the 'admin' or 'secrets_reader' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="roles",
                        required=["admin", "secrets_reader"],
                        actual=sorted(roles),
                        suggestion=f"Add 'admin' or 'secrets_reader' role to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ROLE),
                    ),
                    reason_code=str(DenialReason.MISSING_ROLE),
                ):
                    return result
            stripped_len = len(justification.strip())
            if stripped_len < MIN_JUSTIFICATION:
                detail = (
                    f"SECRETS capabilities require a justification of at least "
                    f"{MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="min_justification",
                        required=MIN_JUSTIFICATION,
                        actual=stripped_len,
                        suggestion=(
                            f"Provide justification with at least {MIN_JUSTIFICATION} "
                            f"characters (currently {stripped_len})"
                        ),
                        reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                    ),
                    reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                ):
                    return result

        # ── Memory checks ────────────────────────────────────────────────
        if capability.sensitivity == SensitivityTag.MEMORY:
            memory_scope = str(request.scope.get("memory_scope", "")) if request.scope else ""
            is_write = capability.safety_class in (
                SafetyClass.WRITE,
                SafetyClass.DESTRUCTIVE,
            )
            if is_write and not (roles & {"memory_writer", "admin"}):
                detail = (
                    f"MEMORY write capabilities require the 'memory_writer' or "
                    f"'admin' role. Principal '{pid}' has roles: {sorted(roles)}."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="roles",
                        required=["memory_writer", "admin"],
                        actual=sorted(roles),
                        suggestion=f"Add 'memory_writer' or 'admin' role to principal '{pid}'",
                        reason_code=str(DenialReason.MEMORY_WRITE_REQUIRES_WRITER),
                    ),
                    reason_code=str(DenialReason.MEMORY_WRITE_REQUIRES_WRITER),
                ):
                    return result
            if (
                not is_write
                and memory_scope == "sensitive"
                and not (roles & {"memory_reader_sensitive", "admin"})
            ):
                detail = (
                    f"MEMORY read with scope='sensitive' requires the "
                    f"'memory_reader_sensitive' or 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="roles",
                        required=["memory_reader_sensitive", "admin"],
                        actual=sorted(roles),
                        suggestion=(
                            f"Add 'memory_reader_sensitive' or 'admin' role to "
                            f"principal '{pid}' (or narrow the request scope away "
                            f"from 'sensitive')"
                        ),
                        reason_code=str(DenialReason.MEMORY_SENSITIVE_READ_DENIED),
                    ),
                    reason_code=str(DenialReason.MEMORY_SENSITIVE_READ_DENIED),
                ):
                    return result

        # ── Row cap ──────────────────────────────────────────────────────
        max_rows = MAX_ROWS_SERVICE if "service" in roles else MAX_ROWS_USER
        if "max_rows" in constraints:
            try:
                requested = int(constraints["max_rows"])
            except (TypeError, ValueError) as exc:
                detail = (
                    f"Invalid 'max_rows' constraint: {constraints['max_rows']!r} "
                    "is not a valid integer."
                )
                if add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="max_rows",
                        required="integer",
                        actual=constraints["max_rows"],
                        suggestion="Provide 'max_rows' as a valid integer",
                        reason_code=str(DenialReason.INVALID_CONSTRAINT),
                    ),
                    reason_code=str(DenialReason.INVALID_CONSTRAINT),
                    cause=exc,
                ):
                    return result
            else:
                constraints["max_rows"] = min(max(requested, 0), max_rows)
                result.trace_steps.append(
                    PolicyTraceStep(
                        name="row_cap",
                        outcome="constraint_applied",
                        detail="max_rows capped",
                    )
                )
        else:
            constraints["max_rows"] = max_rows
            result.trace_steps.append(
                PolicyTraceStep(
                    name="row_cap",
                    outcome="constraint_applied",
                    detail="max_rows capped",
                )
            )

        # ── Rate limiting ────────────────────────────────────────────────
        rate_key = f"{pid}:{cid}"
        if capability.safety_class in self._rate_limits:
            limit, window = self._rate_limits[capability.safety_class]
            if "service" in roles:
                limit *= SERVICE_RATE_MULTIPLIER
            allowed = (
                self._limiter.peek(rate_key, limit, window)
                if read_only
                else self._limiter.check(rate_key, limit, window)
            )
            if not allowed:
                detail = (
                    f"Rate limit exceeded: {limit} {capability.safety_class.value} "
                    f"invocations per {window}s for principal '{pid}'"
                )
                add_failure(
                    detail=detail,
                    condition=FailedCondition(
                        condition="rate_limit",
                        required=f"fewer than {limit} invocations per {window}s",
                        actual="limit exceeded",
                        suggestion=(
                            f"Wait for the {window}s rate-limit window before retrying "
                            f"capability '{cid}'"
                        ),
                        reason_code=str(DenialReason.RATE_LIMITED),
                    ),
                    reason_code=str(DenialReason.RATE_LIMITED),
                )
            elif not read_only:
                self._limiter.record(rate_key)

        return result


__all__ = [
    "DefaultPolicyRuleChain",
    "MAX_ROWS_SERVICE",
    "MAX_ROWS_USER",
    "MIN_JUSTIFICATION",
    "RuleChainResult",
    "RuleFailure",
]
