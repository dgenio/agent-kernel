"""Constraint and rate-limit checks for the default policy chain."""

from __future__ import annotations

from .default_policy_rule_types import (
    MAX_ROWS_SERVICE,
    MAX_ROWS_USER,
    RuleContext,
    RuleFailure,
)
from .models import FailedCondition, PolicyTraceStep
from .policy_reasons import DenialReason
from .rate_limit import SERVICE_RATE_MULTIPLIER


def apply_row_cap(ctx: RuleContext) -> list[RuleFailure]:
    """Validate/cap ``max_rows`` and record the applied constraint."""
    roles = set(ctx.principal.roles)
    max_rows = MAX_ROWS_SERVICE if "service" in roles else MAX_ROWS_USER
    if "max_rows" in ctx.constraints:
        try:
            requested = int(ctx.constraints["max_rows"])
        except (TypeError, ValueError) as exc:
            return [
                RuleFailure(
                    detail=(
                        f"Invalid 'max_rows' constraint: {ctx.constraints['max_rows']!r} "
                        "is not a valid integer."
                    ),
                    condition=FailedCondition(
                        condition="max_rows",
                        required="integer",
                        actual=ctx.constraints["max_rows"],
                        suggestion="Provide 'max_rows' as a valid integer",
                        reason_code=str(DenialReason.INVALID_CONSTRAINT),
                    ),
                    reason_code=str(DenialReason.INVALID_CONSTRAINT),
                    cause=exc,
                )
            ]
        ctx.constraints["max_rows"] = min(max(requested, 0), max_rows)
    else:
        ctx.constraints["max_rows"] = max_rows

    ctx.trace_steps.append(
        PolicyTraceStep(
            name="row_cap",
            outcome="constraint_applied",
            detail="max_rows capped",
        )
    )
    return []


def check_rate_limit(ctx: RuleContext) -> list[RuleFailure]:
    """Check the current sliding window and record usage only for decisions."""
    safety_class = ctx.capability.safety_class
    if safety_class not in ctx.rate_limits:
        return []

    roles = set(ctx.principal.roles)
    limit, window = ctx.rate_limits[safety_class]
    if "service" in roles:
        limit *= SERVICE_RATE_MULTIPLIER
    pid = ctx.principal.principal_id
    cid = ctx.capability.capability_id
    rate_key = f"{pid}:{cid}"
    allowed = (
        ctx.limiter.peek(rate_key, limit, window)
        if ctx.read_only
        else ctx.limiter.check(rate_key, limit, window)
    )
    if not allowed:
        return [
            RuleFailure(
                detail=(
                    f"Rate limit exceeded: {limit} {safety_class.value} "
                    f"invocations per {window}s for principal '{pid}'"
                ),
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
        ]
    if not ctx.read_only:
        ctx.limiter.record(rate_key)
    return []


__all__ = ["apply_row_cap", "check_rate_limit"]
