"""Denial-explanation logic for the declarative policy engine.

Split out of :mod:`policy_dsl` to keep the engine module ≤ 300 lines
(AGENTS.md). The :func:`build_denial_explanation` function performs the
rule traversal that drives :meth:`DeclarativePolicyEngine.explain`. The
engine itself remains the only public entry point — this module is an
implementation detail.
"""

from __future__ import annotations

from .errors import PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    DenialExplanation,
    FailedCondition,
    Principal,
)
from .policy_dsl_parser import PolicyMatch, PolicyRule
from .policy_reasons import DenialReason


def build_denial_explanation(
    rules: list[PolicyRule],
    request: CapabilityRequest,
    capability: Capability,
    principal: Principal,
    *,
    justification: str,
    would_allow: bool,
) -> DenialExplanation:
    """Build a :class:`DenialExplanation` for a request that just denied.

    Args:
        rules: The engine's ordered rule list.
        request: The capability request.
        capability: The target capability.
        principal: The requesting principal.
        justification: Free-text justification.
        would_allow: ``True`` if a fresh :meth:`evaluate` call would allow.
            Callers use this to short-circuit the explanation early; this
            function still receives it because it must return the "would
            be allowed" explanation in that case.
    """
    if would_allow:
        return DenialExplanation(
            denied=False,
            rule_name="",
            failed_conditions=[],
            remediation=[],
            narrative=(
                f"Request for '{capability.capability_id}' by "
                f"'{principal.principal_id}' would be allowed."
            ),
        )

    roles = set(principal.roles)
    pid = principal.principal_id
    explanation_failures: list[FailedCondition] = []
    rule_name = "default-deny"
    primary_code: str | None = str(DenialReason.NO_MATCHING_RULE)

    for rule in rules:
        m = rule.match
        if m.safety_class is not None and capability.safety_class not in m.safety_class:
            continue
        if m.sensitivity is not None and capability.sensitivity not in m.sensitivity:
            continue

        rule_failures = _collect_rule_failures(
            m,
            roles=roles,
            request=request,
            principal=principal,
            justification=justification,
        )

        if rule.action == "deny":
            if not rule_failures:
                rule_name = rule.name
                explanation_failures = [
                    FailedCondition(
                        condition="denied_by_rule",
                        required=f"request must NOT match deny rule '{rule.name}'",
                        actual=f"matched deny rule '{rule.name}'",
                        suggestion=(
                            rule.reason
                            or f"Remove or narrow deny rule '{rule.name}' so this "
                            f"request does not match it"
                        ),
                        reason_code=str(DenialReason.EXPLICIT_DENY_RULE),
                    )
                ]
                primary_code = str(DenialReason.EXPLICIT_DENY_RULE)
                break
            # Partial-match deny rule: it did NOT cause the denial. Skip
            # so we don't suggest changes that would actually trigger it.
            continue

        # Allow rule (structurally matched, conditions unmet) — report it.
        rule_name = rule.name
        explanation_failures = rule_failures
        primary_code = rule_failures[0].reason_code if rule_failures else None
        break

    if not explanation_failures:
        explanation_failures = [
            FailedCondition(
                condition="no_matching_rule",
                required="an allow rule matching this capability",
                actual="no rule matched",
                suggestion=(
                    f"Add an allow rule for safety_class="
                    f"{capability.safety_class.value!r} in your policy file"
                ),
                reason_code=str(DenialReason.NO_MATCHING_RULE),
            )
        ]
        primary_code = str(DenialReason.NO_MATCHING_RULE)

    remediation = [fc.suggestion for fc in explanation_failures]
    narrative = (
        f"Request for '{capability.capability_id}' by '{pid}' would be denied "
        f"(rule: '{rule_name}'): " + "; ".join(fc.suggestion for fc in explanation_failures) + "."
    )
    return DenialExplanation(
        denied=True,
        rule_name=rule_name,
        failed_conditions=explanation_failures,
        remediation=remediation,
        narrative=narrative,
        reason_code=primary_code,
    )


def _collect_rule_failures(
    m: PolicyMatch,
    *,
    roles: set[str],
    request: CapabilityRequest,
    principal: Principal,
    justification: str,
) -> list[FailedCondition]:
    """Return the list of unmet conditions on ``m`` for this principal+request."""
    pid = principal.principal_id
    failures: list[FailedCondition] = []

    if m.roles is not None and not (roles & set(m.roles)):
        failures.append(
            FailedCondition(
                condition="roles",
                required=list(m.roles),
                actual=sorted(roles),
                suggestion=f"Add one of {m.roles!r} to roles for principal '{pid}'",
                reason_code=str(DenialReason.MISSING_ROLE),
            )
        )
    if m.attributes is not None:
        for k, v in m.attributes.items():
            attr_val = principal.attributes.get(k)
            if attr_val is None or (v != "*" and attr_val != v):
                failures.append(
                    FailedCondition(
                        condition=f"attribute:{k}",
                        required=v,
                        actual=attr_val if attr_val is not None else "<absent>",
                        suggestion=f"Set attribute '{k}'={v!r} on principal '{pid}'",
                        reason_code=str(DenialReason.MISSING_ATTRIBUTE),
                    )
                )
    if m.intent is not None and (request.intent is None or request.intent not in m.intent):
        failures.append(
            FailedCondition(
                condition="intent",
                required=list(m.intent),
                actual=request.intent if request.intent is not None else "<absent>",
                suggestion=f"Set CapabilityRequest.intent to one of {m.intent!r}",
                reason_code=str(DenialReason.INTENT_NOT_ALLOWED),
            )
        )
    if m.scope is not None:
        for k, v in m.scope.items():
            scope_val = request.scope.get(k)
            if scope_val is None or (v != "*" and scope_val != v):
                failures.append(
                    FailedCondition(
                        condition=f"scope:{k}",
                        required=v,
                        actual=scope_val if scope_val is not None else "<absent>",
                        suggestion=f"Set CapabilityRequest.scope[{k!r}]={v!r}",
                        reason_code=str(DenialReason.SCOPE_NOT_ALLOWED),
                    )
                )
    if m.min_justification is not None:
        stripped = len(justification.strip())
        if stripped < m.min_justification:
            failures.append(
                FailedCondition(
                    condition="min_justification",
                    required=m.min_justification,
                    actual=stripped,
                    suggestion=(
                        f"Provide justification with at least "
                        f"{m.min_justification} characters (currently {stripped})"
                    ),
                    reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
                )
            )
    return failures


# Re-export so policy_dsl.py only imports one symbol from this module.
__all__ = ["build_denial_explanation", "PolicyDenied"]
