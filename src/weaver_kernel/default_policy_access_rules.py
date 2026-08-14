"""Access, sensitivity, and memory checks for the default policy chain."""

from __future__ import annotations

from .default_policy_rule_types import MIN_JUSTIFICATION, RuleContext, RuleFailure
from .enums import SafetyClass, SensitivityTag
from .models import FailedCondition, PolicyTraceStep
from .policy_reasons import DenialReason


def _justification_failure(ctx: RuleContext, label: str) -> RuleFailure | None:
    stripped_len = len(ctx.justification.strip())
    if stripped_len >= MIN_JUSTIFICATION:
        return None
    detail = (
        f"{label} capabilities require a justification of at least "
        f"{MIN_JUSTIFICATION} characters. Got {len(ctx.justification)} characters "
        f"({stripped_len} after trimming whitespace)."
    )
    return RuleFailure(
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
    )


def check_safety_class(ctx: RuleContext) -> list[RuleFailure]:
    """Apply WRITE/DESTRUCTIVE role and justification requirements."""
    failures: list[RuleFailure] = []
    roles = set(ctx.principal.roles)
    pid = ctx.principal.principal_id

    if ctx.capability.safety_class == SafetyClass.WRITE:
        if not (roles & {"writer", "admin"}):
            failures.append(
                RuleFailure(
                    detail=(
                        "WRITE capabilities require the 'writer' or 'admin' role. "
                        f"Principal '{pid}' has roles: {sorted(roles)}."
                    ),
                    condition=FailedCondition(
                        condition="roles",
                        required=["writer", "admin"],
                        actual=sorted(roles),
                        suggestion=f"Add 'writer' or 'admin' role to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ROLE),
                    ),
                    reason_code=str(DenialReason.MISSING_ROLE),
                )
            )
        failure = _justification_failure(ctx, "WRITE")
        if failure is not None:
            failures.append(failure)

    elif ctx.capability.safety_class == SafetyClass.DESTRUCTIVE:
        if "admin" not in roles:
            failures.append(
                RuleFailure(
                    detail=(
                        "DESTRUCTIVE capabilities require the 'admin' role. "
                        f"Principal '{pid}' has roles: {sorted(roles)}."
                    ),
                    condition=FailedCondition(
                        condition="roles",
                        required=["admin"],
                        actual=sorted(roles),
                        suggestion=f"Add 'admin' role to principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ROLE),
                    ),
                    reason_code=str(DenialReason.MISSING_ROLE),
                )
            )
        failure = _justification_failure(ctx, "DESTRUCTIVE")
        if failure is not None:
            failures.append(failure)

    return failures


def check_tenant_sensitivity(ctx: RuleContext) -> list[RuleFailure]:
    """Apply PII/PCI tenant requirements and allowed-field narrowing."""
    if ctx.capability.sensitivity not in (SensitivityTag.PII, SensitivityTag.PCI):
        return []
    pid = ctx.principal.principal_id
    if "tenant" not in ctx.principal.attributes:
        return [
            RuleFailure(
                detail=(
                    f"Capability '{ctx.capability.capability_id}' has "
                    f"{ctx.capability.sensitivity.value} sensitivity and requires "
                    "the principal to have a 'tenant' attribute."
                ),
                condition=FailedCondition(
                    condition="tenant_attribute",
                    required="present",
                    actual="absent",
                    suggestion=f"Add 'tenant' attribute to principal '{pid}'",
                    reason_code=str(DenialReason.MISSING_TENANT_ATTRIBUTE),
                ),
                reason_code=str(DenialReason.MISSING_TENANT_ATTRIBUTE),
            )
        ]

    roles = set(ctx.principal.roles)
    if ctx.capability.allowed_fields and "pii_reader" not in roles:
        ctx.constraints["allowed_fields"] = ctx.capability.allowed_fields
        ctx.trace_steps.append(
            PolicyTraceStep(
                name="sensitivity:allowed_fields",
                outcome="constraint_applied",
                detail=f"applied allowed_fields={ctx.capability.allowed_fields}",
            )
        )
    return []


def check_secrets(ctx: RuleContext) -> list[RuleFailure]:
    """Apply SECRETS role and justification requirements."""
    if ctx.capability.sensitivity != SensitivityTag.SECRETS:
        return []
    failures: list[RuleFailure] = []
    roles = set(ctx.principal.roles)
    pid = ctx.principal.principal_id
    if not (roles & {"admin", "secrets_reader"}):
        failures.append(
            RuleFailure(
                detail=(
                    "SECRETS capabilities require the 'admin' or 'secrets_reader' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                ),
                condition=FailedCondition(
                    condition="roles",
                    required=["admin", "secrets_reader"],
                    actual=sorted(roles),
                    suggestion=f"Add 'admin' or 'secrets_reader' role to principal '{pid}'",
                    reason_code=str(DenialReason.MISSING_ROLE),
                ),
                reason_code=str(DenialReason.MISSING_ROLE),
            )
        )
    failure = _justification_failure(ctx, "SECRETS")
    if failure is not None:
        failures.append(failure)
    return failures


def check_memory(ctx: RuleContext) -> list[RuleFailure]:
    """Apply MEMORY write and sensitive-read role requirements."""
    if ctx.capability.sensitivity != SensitivityTag.MEMORY:
        return []
    roles = set(ctx.principal.roles)
    pid = ctx.principal.principal_id
    memory_scope = str(ctx.request.scope.get("memory_scope", "")) if ctx.request.scope else ""
    is_write = ctx.capability.safety_class in (SafetyClass.WRITE, SafetyClass.DESTRUCTIVE)

    if is_write and not (roles & {"memory_writer", "admin"}):
        return [
            RuleFailure(
                detail=(
                    "MEMORY write capabilities require the 'memory_writer' or 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}."
                ),
                condition=FailedCondition(
                    condition="roles",
                    required=["memory_writer", "admin"],
                    actual=sorted(roles),
                    suggestion=f"Add 'memory_writer' or 'admin' role to principal '{pid}'",
                    reason_code=str(DenialReason.MEMORY_WRITE_REQUIRES_WRITER),
                ),
                reason_code=str(DenialReason.MEMORY_WRITE_REQUIRES_WRITER),
            )
        ]

    if (
        not is_write
        and memory_scope == "sensitive"
        and not (roles & {"memory_reader_sensitive", "admin"})
    ):
        return [
            RuleFailure(
                detail=(
                    "MEMORY read with scope='sensitive' requires the "
                    f"'memory_reader_sensitive' or 'admin' role. Principal '{pid}' "
                    f"has roles: {sorted(roles)}."
                ),
                condition=FailedCondition(
                    condition="roles",
                    required=["memory_reader_sensitive", "admin"],
                    actual=sorted(roles),
                    suggestion=(
                        f"Add 'memory_reader_sensitive' or 'admin' role to principal '{pid}' "
                        "(or narrow the request scope away from 'sensitive')"
                    ),
                    reason_code=str(DenialReason.MEMORY_SENSITIVE_READ_DENIED),
                ),
                reason_code=str(DenialReason.MEMORY_SENSITIVE_READ_DENIED),
            )
        ]
    return []


__all__ = [
    "check_memory",
    "check_safety_class",
    "check_secrets",
    "check_tenant_sensitivity",
]
