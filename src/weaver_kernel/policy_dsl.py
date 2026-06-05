"""Declarative policy engine: evaluate access-control rules loaded from YAML or TOML.

Parsing and the denial-explanation traversal live in sibling modules
(:mod:`policy_dsl_parser`, :mod:`policy_dsl_explain`) so each module stays
≤ 300 lines per AGENTS.md. :class:`PolicyMatch` and :class:`PolicyRule`
are re-exported from this module for backwards compatibility with the
public API surface (``from weaver_kernel import PolicyMatch, PolicyRule``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from .errors import PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    DenialExplanation,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
)
from .policy_dsl_explain import build_denial_explanation
from .policy_dsl_parser import (
    POLICY_EXTRA_HINT,
    PolicyMatch,
    PolicyRule,
    load_toml_data,
    load_yaml_data,
    parse_engine_data,
)
from .policy_reasons import AllowReason, DenialReason

__all__ = [
    "POLICY_EXTRA_HINT",
    "DeclarativePolicyEngine",
    "PolicyMatch",
    "PolicyRule",
]


class DeclarativePolicyEngine:
    """Policy engine that evaluates rules loaded from YAML or TOML.

    Rules are evaluated top-to-bottom; the first matching rule wins.
    If no rule matches, the *default* action applies (``"deny"`` unless
    overridden). See :mod:`policy_dsl_parser` for the rule schema.
    """

    def __init__(
        self,
        rules: list[PolicyRule],
        *,
        default: Literal["allow", "deny"] = "deny",
    ) -> None:
        """Initialise with a validated rule list.

        Args:
            rules: Ordered list of policy rules (first match wins).
            default: Action when no rule matches. Defaults to ``"deny"``.
        """
        self._rules = rules
        self._default = default

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeclarativePolicyEngine:
        """Build from a plain dict (no file I/O).

        Args:
            data: Dict with a ``rules`` list and an optional ``default`` key.

        Raises:
            PolicyConfigError: If the data is malformed.
        """
        rules, default = parse_engine_data(data)
        return cls(rules, default=default)

    @classmethod
    def from_yaml(cls, path: Path) -> DeclarativePolicyEngine:
        """Build from a YAML file.

        Requires ``pyyaml``: ``pip install 'weaver-kernel[policy]'``.

        Args:
            path: Path to the YAML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed, or
                if ``pyyaml`` is not installed.
        """
        return cls.from_dict(load_yaml_data(path))

    @classmethod
    def from_toml(cls, path: Path) -> DeclarativePolicyEngine:
        """Build from a TOML file.

        Requires Python 3.11+ (stdlib ``tomllib``) or ``tomli`` on 3.10
        (included in ``pip install 'weaver-kernel[policy]'``).

        Args:
            path: Path to the TOML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed.
        """
        return cls.from_dict(load_toml_data(path))

    def _matches(
        self,
        rule: PolicyRule,
        capability: Capability,
        request: CapabilityRequest,
        principal: Principal,
        justification: str,
    ) -> bool:
        m = rule.match
        roles = set(principal.roles)
        if m.safety_class is not None and capability.safety_class not in m.safety_class:
            return False
        if m.sensitivity is not None and capability.sensitivity not in m.sensitivity:
            return False
        if m.roles is not None and not (roles & set(m.roles)):
            return False
        if m.attributes is not None:
            for k, v in m.attributes.items():
                attr_val = principal.attributes.get(k)
                if attr_val is None or (v != "*" and attr_val != v):
                    return False
        if m.intent is not None and (request.intent is None or request.intent not in m.intent):
            return False
        if m.scope is not None:
            for k, v in m.scope.items():
                scope_val = request.scope.get(k)
                if scope_val is None or (v != "*" and scope_val != v):
                    return False
        return m.min_justification is None or len(justification.strip()) >= m.min_justification

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate rules top-to-bottom; first match wins.

        Args:
            request: The capability request.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification.

        Returns:
            :class:`PolicyDecision` with ``allowed=True`` and merged constraints.

        Raises:
            PolicyDenied: If a deny rule matches or the default action is deny.
        """
        constraints = dict(request.constraints)
        pid = principal.principal_id
        cid = capability.capability_id

        trace = PolicyDecisionTrace(
            engine="DeclarativePolicyEngine",
            capability_id=cid,
            principal_id=pid,
            intent=request.intent,
            scope_keys=sorted(request.scope.keys()),
        )

        for rule in self._rules:
            if not self._matches(rule, capability, request, principal, justification):
                trace.steps.append(
                    PolicyTraceStep(
                        name=f"rule:{rule.name}",
                        outcome="skipped",
                        detail="match clause did not match",
                    )
                )
                continue
            trace.steps.append(
                PolicyTraceStep(
                    name=f"rule:{rule.name}",
                    outcome="matched",
                    detail=f"action={rule.action!r}",
                )
            )
            if rule.action == "deny":
                detail = rule.reason or f"Denied by rule '{rule.name}'."
                trace.steps.append(
                    PolicyTraceStep(
                        name=f"rule:{rule.name}",
                        outcome="denied",
                        detail=detail,
                        reason_code=str(DenialReason.EXPLICIT_DENY_RULE),
                    )
                )
                trace.final_outcome = "denied"
                trace.final_reason_code = str(DenialReason.EXPLICIT_DENY_RULE)
                raise PolicyDenied(detail, reason_code=str(DenialReason.EXPLICIT_DENY_RULE))
            constraints.update(rule.constraints)
            if rule.constraints:
                trace.steps.append(
                    PolicyTraceStep(
                        name=f"rule:{rule.name}",
                        outcome="constraint_applied",
                        detail=f"applied constraints={sorted(rule.constraints)}",
                    )
                )
            reason = f"Allowed by rule '{rule.name}'."
            trace.steps.append(
                PolicyTraceStep(
                    name=f"rule:{rule.name}",
                    outcome="allowed",
                    detail=reason,
                    reason_code=str(AllowReason.RULE_ALLOW),
                )
            )
            trace.final_outcome = "allowed"
            trace.final_reason_code = str(AllowReason.RULE_ALLOW)
            return PolicyDecision(
                allowed=True,
                reason=reason,
                constraints=constraints,
                reason_code=str(AllowReason.RULE_ALLOW),
                trace=trace,
            )

        if self._default == "deny":
            detail = (
                f"No policy rule matched request for capability '{cid}' "
                f"by principal '{pid}'. Default action is deny."
            )
            trace.steps.append(
                PolicyTraceStep(
                    name="default",
                    outcome="denied",
                    detail=detail,
                    reason_code=str(DenialReason.NO_MATCHING_RULE),
                )
            )
            trace.final_outcome = "denied"
            trace.final_reason_code = str(DenialReason.NO_MATCHING_RULE)
            raise PolicyDenied(detail, reason_code=str(DenialReason.NO_MATCHING_RULE))
        trace.steps.append(
            PolicyTraceStep(
                name="default",
                outcome="allowed",
                detail="No rule matched; default action is allow.",
                reason_code=str(AllowReason.DEFAULT_FALLTHROUGH_ALLOW),
            )
        )
        trace.final_outcome = "allowed"
        trace.final_reason_code = str(AllowReason.DEFAULT_FALLTHROUGH_ALLOW)
        return PolicyDecision(
            allowed=True,
            reason="No rule matched; default action is allow.",
            constraints=constraints,
            reason_code=str(AllowReason.DEFAULT_FALLTHROUGH_ALLOW),
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
        """Explain which rule conditions prevented a match.

        Takes the fast path first: if the request would be allowed, returns
        ``denied=False`` immediately. Otherwise, finds the rule that explains
        the denial — either an explicit deny rule that fully matches, or the
        first structurally-matching allow rule whose unmet conditions are
        reported. Partial-match deny rules are skipped (they did not cause
        the denial, and suggesting how to satisfy them would be misleading —
        satisfying them would only trigger the deny).
        """
        try:
            self.evaluate(request, capability, principal, justification=justification)
            would_allow = True
        except PolicyDenied:
            would_allow = False

        return build_denial_explanation(
            self._rules,
            request,
            capability,
            principal,
            justification=justification,
            would_allow=would_allow,
        )
