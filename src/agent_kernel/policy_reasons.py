"""Stable machine-readable reason codes for policy decisions.

Reason codes are part of the policy decision contract: downstream code,
tests, metrics, and UI mapping should assert on these stable values rather
than matching the human-readable ``reason`` strings on :class:`PolicyDecision`
and :class:`DenialExplanation`, which are explicitly allowed to evolve.

The values are short, lowercase, ``snake_case`` identifiers. New codes may be
added; existing codes are not renamed without a deprecation cycle.
"""

from __future__ import annotations

from enum import Enum


class _StrEnumCompat(str, Enum):
    """``(str, Enum)`` mixin with ``StrEnum``-style ``__str__`` for Python 3.10 compat.

    On Python 3.11+ ``enum.StrEnum`` already produces ``str(member) == member.value``.
    Plain ``(str, Enum)`` instead returns ``"ClassName.MEMBER"`` from ``__str__``,
    which is unhelpful for codes that are meant to be the value itself. We override
    ``__str__`` so callers can do ``str(DenialReason.MISSING_ROLE) == "missing_role"``
    uniformly across all supported Python versions.
    """

    def __str__(self) -> str:
        return str(self.value)


class DenialReason(_StrEnumCompat):
    """Stable codes describing why a policy decision denied a request.

    Used as :attr:`PolicyDecision.reason_code`,
    :attr:`DenialExplanation.reason_code`, :attr:`FailedCondition.reason_code`,
    and :attr:`agent_kernel.PolicyDenied.reason_code`.
    """

    # Role / identity
    MISSING_ROLE = "missing_role"
    """Principal lacks a required role (e.g. ``writer``, ``admin``)."""

    MISSING_TENANT_ATTRIBUTE = "missing_tenant_attribute"
    """PII/PCI capability requires the ``tenant`` attribute on the principal."""

    MISSING_ATTRIBUTE = "missing_attribute"
    """A declarative rule's required attribute is absent or has the wrong value."""

    # Justification
    INSUFFICIENT_JUSTIFICATION = "insufficient_justification"
    """Caller-provided justification is shorter than the policy minimum."""

    # Constraints
    INVALID_CONSTRAINT = "invalid_constraint"
    """A constraint value (e.g. ``max_rows``) is not parseable or in range."""

    # Rate limiting
    RATE_LIMITED = "rate_limited"
    """The sliding-window rate limit for this principal/capability was exceeded."""

    # Declarative engine
    NO_MATCHING_RULE = "no_matching_rule"
    """No rule matched and the engine's default action is ``deny``."""

    EXPLICIT_DENY_RULE = "explicit_deny_rule"
    """A declarative rule with ``action: deny`` matched the request."""

    # Intent / scope (#72)
    INTENT_NOT_ALLOWED = "intent_not_allowed"
    """A declarative rule restricted the allowed intents and the request's intent is not in that set."""

    SCOPE_NOT_ALLOWED = "scope_not_allowed"
    """A declarative rule restricted scope values and the request's scope does not match."""


class AllowReason(_StrEnumCompat):
    """Stable codes describing why a policy decision allowed a request."""

    DEFAULT_POLICY_ALLOW = "default_policy_allow"
    """Allowed by :class:`DefaultPolicyEngine` after all rule checks passed."""

    RULE_ALLOW = "rule_allow"
    """Allowed by a matching ``action: allow`` rule in :class:`DeclarativePolicyEngine`."""

    DEFAULT_FALLTHROUGH_ALLOW = "default_fallthrough_allow"
    """Allowed because no rule matched and the engine's default action is ``allow``."""

    TOKEN_VERIFIED = "token_verified"
    """Allowed in dry-run: the token was verified; policy was evaluated at grant time."""


__all__ = ["AllowReason", "DenialReason"]
