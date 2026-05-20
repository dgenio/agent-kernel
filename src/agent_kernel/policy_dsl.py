"""Declarative policy engine: load access-control rules from YAML or TOML.

The YAML/TOML loaders import their parsers lazily, so ``import agent_kernel``
works without the optional ``policy`` extra installed. Calling
:meth:`DeclarativePolicyEngine.from_yaml` or :meth:`from_toml` without the
required parser surfaces a :class:`PolicyConfigError` with an install hint.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .enums import SafetyClass, SensitivityTag
from .errors import PolicyConfigError, PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    DenialExplanation,
    FailedCondition,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
)
from .policy_reasons import AllowReason, DenialReason

# Hint surfaced when the optional ``policy`` extra is missing.
_POLICY_EXTRA_HINT = (
    "Install the policy extra to enable file loaders: pip install 'weaver-kernel[policy]'"
)


@dataclass(slots=True)
class PolicyMatch:
    """Conditions that must ALL be satisfied for a rule to match a request.

    ``None`` fields are wildcards — they match any value.
    List fields use ANY-of semantics (e.g. ``roles = ["a", "b"]`` matches
    if the principal has *at least one* of those roles).
    """

    safety_class: list[SafetyClass] | None = None
    """Match if ``capability.safety_class`` is in this list."""

    sensitivity: list[SensitivityTag] | None = None
    """Match if ``capability.sensitivity`` is in this list."""

    roles: list[str] | None = None
    """Match if the principal has ANY of these roles."""

    attributes: dict[str, str] | None = None
    """Match if the principal has ALL these attributes.
    Use ``"*"`` as the value to require the attribute with any value."""

    min_justification: int | None = None
    """Match if ``len(justification.strip()) >= min_justification``."""

    intent: list[str] | None = None
    """Match if :attr:`CapabilityRequest.intent` is in this list.

    A non-``None`` list means "this rule is intent-aware". A request with
    :attr:`CapabilityRequest.intent` ``None`` never matches an intent-aware
    rule (so policies that require an intent fail closed for unstructured
    legacy callers).
    """

    scope: dict[str, str] | None = None
    """Match if :attr:`CapabilityRequest.scope` contains ALL these key/value pairs.
    Use ``"*"`` as the value to require the key with any value.
    """


@dataclass(slots=True)
class PolicyRule:
    """A single declarative policy rule."""

    name: str
    match: PolicyMatch
    action: Literal["allow", "deny"]
    constraints: dict[str, Any] = field(default_factory=dict)
    """Extra constraints merged into the :class:`PolicyDecision` on allow."""

    reason: str = ""
    """Human-readable reason embedded in :class:`PolicyDenied` on deny."""


class DeclarativePolicyEngine:
    """Policy engine that evaluates rules loaded from YAML or TOML.

    Rules are evaluated top-to-bottom; the first matching rule wins.
    If no rule matches, the *default* action applies (``"deny"`` unless
    overridden).

    Example::

        engine = DeclarativePolicyEngine.from_yaml(Path("policy.yaml"))
        decision = engine.evaluate(request, capability, principal, justification="...")
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

    # ── Loaders ───────────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeclarativePolicyEngine:
        """Build from a plain dict (no file I/O).

        Args:
            data: Dict with a ``rules`` list and an optional ``default`` key.

        Raises:
            PolicyConfigError: If the data is malformed.
        """
        return cls._parse(data)

    @classmethod
    def from_yaml(cls, path: Path) -> DeclarativePolicyEngine:
        """Build from a YAML file.

        Requires ``pyyaml``: ``pip install 'weaver-kernel[policy]'``.
        The import is deferred so that ``import agent_kernel`` works without
        the policy extra installed.

        Args:
            path: Path to the YAML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed, or
                if ``pyyaml`` is not installed.
        """
        try:
            import yaml
        except ImportError as exc:
            raise PolicyConfigError(_POLICY_EXTRA_HINT) from exc

        try:
            text = path.read_text(encoding="utf-8")
            data: Any = yaml.safe_load(text)
        except OSError as exc:
            raise PolicyConfigError(f"Cannot read policy file '{path}': {exc}") from exc
        except yaml.YAMLError as exc:
            raise PolicyConfigError(f"YAML parse error in '{path}': {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyConfigError(f"Policy file '{path}' must be a YAML mapping.")
        return cls._parse(data)

    @classmethod
    def from_toml(cls, path: Path) -> DeclarativePolicyEngine:
        """Build from a TOML file.

        Requires Python 3.11+ (stdlib ``tomllib``) or ``tomli`` on 3.10
        (included in ``pip install 'weaver-kernel[policy]'``). The import is
        deferred so that ``import agent_kernel`` works without the policy
        extra installed.

        Args:
            path: Path to the TOML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed, or
                if neither ``tomllib`` nor ``tomli`` is available.
        """
        try:
            if sys.version_info >= (3, 11):
                import tomllib as _toml
            else:
                import tomli as _toml
        except ImportError as exc:
            raise PolicyConfigError(_POLICY_EXTRA_HINT) from exc

        try:
            with path.open("rb") as fh:
                data = _toml.load(fh)
        except OSError as exc:
            raise PolicyConfigError(f"Cannot read policy file '{path}': {exc}") from exc
        except Exception as exc:  # TOMLDecodeError is not a stable import target
            raise PolicyConfigError(f"TOML parse error in '{path}': {exc}") from exc
        return cls._parse(data)

    # ── Parsing ───────────────────────────────────────────────────────────────

    @classmethod
    def _parse(cls, data: dict[str, Any]) -> DeclarativePolicyEngine:
        raw_default = data.get("default", "deny")
        if raw_default not in ("allow", "deny"):
            raise PolicyConfigError(f"'default' must be 'allow' or 'deny', got {raw_default!r}.")
        default: Literal["allow", "deny"] = raw_default

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise PolicyConfigError("'rules' must be a list.")

        return cls(
            [cls._parse_rule(r, index=i) for i, r in enumerate(raw_rules)],
            default=default,
        )

    @classmethod
    def _parse_rule(cls, raw: Any, *, index: int) -> PolicyRule:
        if not isinstance(raw, dict):
            raise PolicyConfigError(f"Rule[{index}] must be a mapping, got {type(raw).__name__}.")
        name: str = raw.get("name", f"rule-{index}")
        action = raw.get("action")
        if action not in ("allow", "deny"):
            raise PolicyConfigError(
                f"Rule '{name}': 'action' must be 'allow' or 'deny', got {action!r}."
            )
        raw_match = raw.get("match", {})
        if not isinstance(raw_match, dict):
            raise PolicyConfigError(f"Rule '{name}': 'match' must be a mapping.")

        safety_class: list[SafetyClass] | None = None
        if "safety_class" in raw_match:
            try:
                safety_class = [SafetyClass(v) for v in raw_match["safety_class"]]
            except ValueError as exc:
                raise PolicyConfigError(
                    f"Rule '{name}': invalid safety_class value: {exc}"
                ) from exc

        sensitivity: list[SensitivityTag] | None = None
        if "sensitivity" in raw_match:
            try:
                sensitivity = [SensitivityTag(v) for v in raw_match["sensitivity"]]
            except ValueError as exc:
                raise PolicyConfigError(
                    f"Rule '{name}': invalid sensitivity value: {exc}"
                ) from exc

        roles: list[str] | None = None
        if "roles" in raw_match:
            roles_raw = raw_match["roles"]
            if not isinstance(roles_raw, list) or not all(isinstance(r, str) for r in roles_raw):
                raise PolicyConfigError(
                    f"Rule '{name}': 'roles' must be a list of strings, "
                    f"got {type(roles_raw).__name__}."
                )
            roles = list(roles_raw)

        attributes: dict[str, str] | None = None
        if "attributes" in raw_match:
            attrs_raw = raw_match["attributes"]
            if not isinstance(attrs_raw, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in attrs_raw.items()
            ):
                raise PolicyConfigError(
                    f"Rule '{name}': 'attributes' must be a mapping of "
                    f"string keys to string values."
                )
            attributes = dict(attrs_raw)

        min_justification: int | None = None
        if "min_justification" in raw_match:
            mj_raw = raw_match["min_justification"]
            # ``bool`` is a subclass of ``int`` in Python; reject it explicitly
            # so ``min_justification: true`` does not silently pass.
            if not isinstance(mj_raw, int) or isinstance(mj_raw, bool):
                raise PolicyConfigError(
                    f"Rule '{name}': 'min_justification' must be an integer, "
                    f"got {type(mj_raw).__name__}."
                )
            min_justification = mj_raw

        intent: list[str] | None = None
        if "intent" in raw_match:
            intent_raw = raw_match["intent"]
            if not isinstance(intent_raw, list) or not all(isinstance(i, str) for i in intent_raw):
                raise PolicyConfigError(
                    f"Rule '{name}': 'intent' must be a list of strings, "
                    f"got {type(intent_raw).__name__}."
                )
            intent = list(intent_raw)

        scope: dict[str, str] | None = None
        if "scope" in raw_match:
            scope_raw = raw_match["scope"]
            if not isinstance(scope_raw, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in scope_raw.items()
            ):
                raise PolicyConfigError(
                    f"Rule '{name}': 'scope' must be a mapping of string keys to string values."
                )
            scope = dict(scope_raw)

        constraints_raw = raw.get("constraints", {})
        if not isinstance(constraints_raw, dict):
            raise PolicyConfigError(
                f"Rule '{name}': 'constraints' must be a mapping, "
                f"got {type(constraints_raw).__name__}."
            )

        return PolicyRule(
            name=name,
            match=PolicyMatch(
                safety_class=safety_class,
                sensitivity=sensitivity,
                roles=roles,
                attributes=attributes,
                min_justification=min_justification,
                intent=intent,
                scope=scope,
            ),
            action=action,
            constraints=dict(constraints_raw),
            reason=raw.get("reason", ""),
        )

    # ── Matching ──────────────────────────────────────────────────────────────

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

    # ── Evaluation ────────────────────────────────────────────────────────────

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

        Args:
            request: The capability request.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification.

        Returns:
            :class:`DenialExplanation` with ``denied=False`` if allowed.
        """
        try:
            self.evaluate(request, capability, principal, justification=justification)
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
        except PolicyDenied:
            pass

        roles = set(principal.roles)
        pid = principal.principal_id
        explanation_failures: list[FailedCondition] = []
        rule_name = "default-deny"
        primary_code: str | None = str(DenialReason.NO_MATCHING_RULE)

        for rule in self._rules:
            m = rule.match
            if m.safety_class is not None and capability.safety_class not in m.safety_class:
                continue
            if m.sensitivity is not None and capability.sensitivity not in m.sensitivity:
                continue

            # Collect unmet conditions for this rule.
            rule_failures: list[FailedCondition] = []
            if m.roles is not None and not (roles & set(m.roles)):
                rule_failures.append(
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
                        rule_failures.append(
                            FailedCondition(
                                condition=f"attribute:{k}",
                                required=v,
                                actual=attr_val if attr_val is not None else "<absent>",
                                suggestion=f"Set attribute '{k}'={v!r} on principal '{pid}'",
                                reason_code=str(DenialReason.MISSING_ATTRIBUTE),
                            )
                        )
            if m.intent is not None and (request.intent is None or request.intent not in m.intent):
                rule_failures.append(
                    FailedCondition(
                        condition="intent",
                        required=list(m.intent),
                        actual=request.intent if request.intent is not None else "<absent>",
                        suggestion=(f"Set CapabilityRequest.intent to one of {m.intent!r}"),
                        reason_code=str(DenialReason.INTENT_NOT_ALLOWED),
                    )
                )
            if m.scope is not None:
                for k, v in m.scope.items():
                    scope_val = request.scope.get(k)
                    if scope_val is None or (v != "*" and scope_val != v):
                        rule_failures.append(
                            FailedCondition(
                                condition=f"scope:{k}",
                                required=v,
                                actual=scope_val if scope_val is not None else "<absent>",
                                suggestion=(f"Set CapabilityRequest.scope[{k!r}]={v!r}"),
                                reason_code=str(DenialReason.SCOPE_NOT_ALLOWED),
                            )
                        )
            if m.min_justification is not None:
                stripped = len(justification.strip())
                if stripped < m.min_justification:
                    rule_failures.append(
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

            if rule.action == "deny":
                if not rule_failures:
                    # Explicit deny rule fully matched — this is the cause.
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
            f"(rule: '{rule_name}'): "
            + "; ".join(fc.suggestion for fc in explanation_failures)
            + "."
        )
        return DenialExplanation(
            denied=True,
            rule_name=rule_name,
            failed_conditions=explanation_failures,
            remediation=remediation,
            narrative=narrative,
            reason_code=primary_code,
        )
