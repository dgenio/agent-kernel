"""Declarative policy engine: load access-control rules from YAML or TOML."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import yaml

from .enums import SafetyClass, SensitivityTag
from .errors import PolicyConfigError, PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    DenialExplanation,
    FailedCondition,
    PolicyDecision,
    Principal,
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

        Args:
            path: Path to the YAML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed.
        """
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
        (both included in ``pip install 'weaver-kernel[policy]'``).

        Args:
            path: Path to the TOML policy file.

        Raises:
            PolicyConfigError: If the file is unreadable or malformed.
        """
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
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

        return PolicyRule(
            name=name,
            match=PolicyMatch(
                safety_class=safety_class,
                sensitivity=sensitivity,
                roles=raw_match.get("roles"),
                attributes=raw_match.get("attributes"),
                min_justification=raw_match.get("min_justification"),
            ),
            action=action,
            constraints=raw.get("constraints", {}),
            reason=raw.get("reason", ""),
        )

    # ── Matching ──────────────────────────────────────────────────────────────

    def _matches(
        self,
        rule: PolicyRule,
        capability: Capability,
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

        for rule in self._rules:
            if not self._matches(rule, capability, principal, justification):
                continue
            if rule.action == "deny":
                raise PolicyDenied(rule.reason or f"Denied by rule '{rule.name}'.")
            constraints.update(rule.constraints)
            return PolicyDecision(
                allowed=True,
                reason=f"Allowed by rule '{rule.name}'.",
                constraints=constraints,
            )

        if self._default == "deny":
            raise PolicyDenied(
                f"No policy rule matched request for capability '{cid}' "
                f"by principal '{pid}'. Default action is deny."
            )
        return PolicyDecision(
            allowed=True,
            reason="No rule matched; default action is allow.",
            constraints=constraints,
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
        ``denied=False`` immediately. Otherwise, finds the first rule that
        structurally matches (by safety_class / sensitivity) and reports which
        of its remaining conditions were not met.

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

        # Find the first rule that structurally targets this capability type
        # and report which of its conditions blocked the match.
        roles = set(principal.roles)
        pid = principal.principal_id
        failed: list[FailedCondition] = []
        rule_name = "default-deny"

        for rule in self._rules:
            m = rule.match
            if m.safety_class is not None and capability.safety_class not in m.safety_class:
                continue
            if m.sensitivity is not None and capability.sensitivity not in m.sensitivity:
                continue
            rule_name = rule.name
            if m.roles is not None and not (roles & set(m.roles)):
                failed.append(
                    FailedCondition(
                        condition="roles",
                        required=list(m.roles),
                        actual=sorted(roles),
                        suggestion=f"Add one of {m.roles!r} to roles for principal '{pid}'",
                    )
                )
            if m.attributes is not None:
                for k, v in m.attributes.items():
                    attr_val = principal.attributes.get(k)
                    if attr_val is None or (v != "*" and attr_val != v):
                        failed.append(
                            FailedCondition(
                                condition=f"attribute:{k}",
                                required=v,
                                actual=attr_val if attr_val is not None else "<absent>",
                                suggestion=f"Set attribute '{k}'={v!r} on principal '{pid}'",
                            )
                        )
            if m.min_justification is not None:
                stripped = len(justification.strip())
                if stripped < m.min_justification:
                    failed.append(
                        FailedCondition(
                            condition="min_justification",
                            required=m.min_justification,
                            actual=stripped,
                            suggestion=(
                                f"Provide justification with at least "
                                f"{m.min_justification} characters (currently {stripped})"
                            ),
                        )
                    )
            break  # explain from the first structurally-matching rule only

        if not failed:
            failed.append(
                FailedCondition(
                    condition="no_matching_rule",
                    required="an allow rule matching this capability",
                    actual="no rule matched",
                    suggestion=(
                        f"Add an allow rule for safety_class="
                        f"{capability.safety_class.value!r} in your policy file"
                    ),
                )
            )

        remediation = [fc.suggestion for fc in failed]
        narrative = (
            f"Request for '{capability.capability_id}' by '{pid}' would be denied "
            f"(rule: '{rule_name}'): " + "; ".join(fc.suggestion for fc in failed) + "."
        )
        return DenialExplanation(
            denied=True,
            rule_name=rule_name,
            failed_conditions=failed,
            remediation=remediation,
            narrative=narrative,
        )
