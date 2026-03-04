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
