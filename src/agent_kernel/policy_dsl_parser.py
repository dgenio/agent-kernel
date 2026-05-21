"""Parsing and schema for the declarative policy engine.

Split out of :mod:`policy_dsl` to keep individual modules ≤ 300 lines
(AGENTS.md quality bar). The :class:`PolicyMatch` and :class:`PolicyRule`
dataclasses live here because the parser produces them; the engine in
:mod:`policy_dsl` re-exports them so the public API is unchanged.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .enums import SafetyClass, SensitivityTag
from .errors import PolicyConfigError

POLICY_EXTRA_HINT = (
    "Install the policy extra to enable file loaders: pip install 'weaver-kernel[policy]'"
)
"""Install hint surfaced when the optional ``policy`` extra is missing."""


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


def parse_engine_data(data: dict[str, Any]) -> tuple[list[PolicyRule], Literal["allow", "deny"]]:
    """Parse a top-level policy mapping into ``(rules, default)``.

    Args:
        data: Mapping with a ``rules`` list and an optional ``default`` key.

    Returns:
        A ``(rules, default)`` pair. ``default`` is the literal ``"allow"`` or
        ``"deny"``; ``rules`` is the parsed rule list (may be empty).

    Raises:
        PolicyConfigError: If the mapping is malformed.
    """
    raw_default = data.get("default", "deny")
    if raw_default not in ("allow", "deny"):
        raise PolicyConfigError(f"'default' must be 'allow' or 'deny', got {raw_default!r}.")
    default: Literal["allow", "deny"] = raw_default

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyConfigError("'rules' must be a list.")

    rules = [parse_rule(r, index=i) for i, r in enumerate(raw_rules)]
    return rules, default


def parse_rule(raw: Any, *, index: int) -> PolicyRule:
    """Parse a single rule mapping into a :class:`PolicyRule`.

    Args:
        raw: The rule mapping.
        index: Position in the rules list (used in error messages when the
            rule has no explicit ``name``).

    Raises:
        PolicyConfigError: If the rule is malformed.
    """
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

    match = PolicyMatch(
        safety_class=_parse_enum_list(raw_match, "safety_class", SafetyClass, rule_name=name),
        sensitivity=_parse_enum_list(raw_match, "sensitivity", SensitivityTag, rule_name=name),
        roles=_parse_str_list(raw_match, "roles", rule_name=name),
        attributes=_parse_str_map(raw_match, "attributes", rule_name=name),
        min_justification=_parse_min_justification(raw_match, rule_name=name),
        intent=_parse_str_list(raw_match, "intent", rule_name=name),
        scope=_parse_str_map(raw_match, "scope", rule_name=name),
    )

    constraints_raw = raw.get("constraints", {})
    if not isinstance(constraints_raw, dict):
        raise PolicyConfigError(
            f"Rule '{name}': 'constraints' must be a mapping, "
            f"got {type(constraints_raw).__name__}."
        )

    return PolicyRule(
        name=name,
        match=match,
        action=action,
        constraints=dict(constraints_raw),
        reason=raw.get("reason", ""),
    )


def load_yaml_data(path: Path) -> dict[str, Any]:
    """Read a YAML file into a top-level mapping.

    Requires ``pyyaml``: ``pip install 'weaver-kernel[policy]'``. The import is
    deferred so that ``import agent_kernel`` works without the policy extra.

    Raises:
        PolicyConfigError: If the file is unreadable, malformed, or pyyaml
            is not installed.
    """
    try:
        import yaml
    except ImportError as exc:
        raise PolicyConfigError(POLICY_EXTRA_HINT) from exc

    try:
        text = path.read_text(encoding="utf-8")
        data: Any = yaml.safe_load(text)
    except OSError as exc:
        raise PolicyConfigError(f"Cannot read policy file '{path}': {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"YAML parse error in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyConfigError(f"Policy file '{path}' must be a YAML mapping.")
    return data


def load_toml_data(path: Path) -> dict[str, Any]:
    """Read a TOML file into a top-level mapping.

    Uses stdlib ``tomllib`` on 3.11+ and ``tomli`` on 3.10. The latter is
    included by the ``policy`` extra.

    Raises:
        PolicyConfigError: If the file is unreadable, malformed, or no TOML
            parser is available.
    """
    try:
        if sys.version_info >= (3, 11):
            import tomllib as _toml
        else:
            import tomli as _toml
    except ImportError as exc:
        raise PolicyConfigError(POLICY_EXTRA_HINT) from exc

    try:
        with path.open("rb") as fh:
            data = _toml.load(fh)
    except OSError as exc:
        raise PolicyConfigError(f"Cannot read policy file '{path}': {exc}") from exc
    except Exception as exc:  # TOMLDecodeError is not a stable import target
        raise PolicyConfigError(f"TOML parse error in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyConfigError(f"Policy file '{path}' must be a TOML table.")
    return data


# ── Field validators ────────────────────────────────────────────────────────


def _parse_enum_list(
    raw_match: dict[str, Any],
    key: str,
    enum_cls: type[SafetyClass] | type[SensitivityTag],
    *,
    rule_name: str,
) -> list[Any] | None:
    if key not in raw_match:
        return None
    try:
        return [enum_cls(v) for v in raw_match[key]]
    except (ValueError, TypeError) as exc:
        raise PolicyConfigError(f"Rule '{rule_name}': invalid {key} value: {exc}") from exc


def _parse_str_list(raw_match: dict[str, Any], key: str, *, rule_name: str) -> list[str] | None:
    if key not in raw_match:
        return None
    value = raw_match[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyConfigError(
            f"Rule '{rule_name}': {key!r} must be a list of strings, got {type(value).__name__}."
        )
    return list(value)


def _parse_str_map(
    raw_match: dict[str, Any], key: str, *, rule_name: str
) -> dict[str, str] | None:
    if key not in raw_match:
        return None
    value = raw_match[key]
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise PolicyConfigError(
            f"Rule '{rule_name}': {key!r} must be a mapping of string keys to string values."
        )
    return dict(value)


def _parse_min_justification(raw_match: dict[str, Any], *, rule_name: str) -> int | None:
    if "min_justification" not in raw_match:
        return None
    value = raw_match["min_justification"]
    # ``bool`` is a subclass of ``int`` in Python; reject it explicitly
    # so ``min_justification: true`` does not silently pass.
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyConfigError(
            f"Rule '{rule_name}': 'min_justification' must be an integer, "
            f"got {type(value).__name__}."
        )
    return value


__all__ = [
    "POLICY_EXTRA_HINT",
    "PolicyMatch",
    "PolicyRule",
    "parse_engine_data",
    "parse_rule",
    "load_yaml_data",
    "load_toml_data",
]
