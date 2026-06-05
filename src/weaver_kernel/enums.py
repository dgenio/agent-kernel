"""Enumerations for SafetyClass and SensitivityTag."""

from enum import Enum


class SafetyClass(str, Enum):
    """Classifies the danger level of a capability's side-effects."""

    READ = "READ"
    """No side-effects; safe to retry."""

    WRITE = "WRITE"
    """Mutates state; requires justification and writer/admin role."""

    DESTRUCTIVE = "DESTRUCTIVE"
    """Irreversible; requires admin role."""


class SensitivityTag(str, Enum):
    """Tags data sensitivity requirements on a capability."""

    NONE = "NONE"
    """No special sensitivity."""

    PII = "PII"
    """Personally identifiable information (name, email, phone, SSN)."""

    PCI = "PCI"
    """Payment card industry data (card numbers, CVV)."""

    SECRETS = "SECRETS"
    """Credentials, API keys, tokens."""

    MEMORY = "MEMORY"
    """Durable agent memory (project notes, session handoff, learned context).

    Reading durable memory may expose sensitive past context; writing creates
    durable assumptions that persist into future sessions. Policy treats
    writes as higher risk than reads. See ``DefaultPolicyEngine.evaluate``.
    """
