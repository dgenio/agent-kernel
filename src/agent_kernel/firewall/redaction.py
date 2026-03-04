"""PII/PCI field redaction for the context firewall."""

from __future__ import annotations

import re
from typing import Any

# Fields that are always redacted when PII/PCI sensitivity is active
# (unless the principal has the pii_reader role).
_SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "email",
        "phone",
        "card_number",
        "ssn",
        "social_security_number",
        "cvv",
        "credit_card",
        "password",
        "secret",
    }
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_RE = re.compile(
    r"""
    (?<!\d)(?<![./])               # not preceded by digit, dot, or slash
    (?:\+\d{1,3}[\s.\-])?         # optional intl prefix  (+1, +44 20)
    (?:                            # area / city code
      \(\d{2,4}\)[\s.\-]?         #   (555)  or  (020)
    | \d{2,4}[\s.\-]              #   555-   or  020.
    )
    \d{3,4}                        # subscriber part 1
    [\s.\-]?                       # optional separator
    \d{3,5}                        # subscriber part 2
    (?!\d)(?![./])                 # not followed by digit, dot, or slash
    """,
    re.VERBOSE,
)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_SSN_RE = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")

_REDACTED = "[REDACTED]"


def _is_sensitive_field_name(name: str) -> bool:
    return name.lower() in _SENSITIVE_FIELDS


def redact(
    data: Any,
    *,
    allowed_fields: list[str] | None = None,
    depth: int = 0,
    max_depth: int = 3,
) -> tuple[Any, list[str]]:
    """Recursively redact sensitive data from *data*.

    If *allowed_fields* is non-empty, only those fields are kept in dicts;
    all others are removed.  Sensitive field names are replaced with
    ``[REDACTED]`` regardless.

    Args:
        data: The data to redact.
        allowed_fields: If non-empty, only keep these field names in dicts.
        depth: Current recursion depth (used internally).
        max_depth: Maximum recursion depth.

    Returns:
        A tuple of ``(redacted_data, warnings)`` where *warnings* is a list of
        human-readable strings describing what was redacted.
    """
    warnings: list[str] = []

    if depth >= max_depth:
        return data, warnings

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            if allowed_fields and k not in allowed_fields:
                warnings.append(f"Field '{k}' omitted (not in allowed_fields).")
                continue
            if _is_sensitive_field_name(str(k)):
                result[k] = _REDACTED
                warnings.append(f"Field '{k}' redacted (sensitive field name).")
            else:
                child, child_warnings = redact(
                    v, allowed_fields=None, depth=depth + 1, max_depth=max_depth
                )
                result[k] = child
                warnings.extend(child_warnings)
        return result, warnings

    if isinstance(data, list):
        redacted_list = []
        for item in data:
            child, child_warnings = redact(
                item, allowed_fields=allowed_fields, depth=depth + 1, max_depth=max_depth
            )
            redacted_list.append(child)
            warnings.extend(child_warnings)
        return redacted_list, warnings

    if isinstance(data, str):
        original = data
        data = _EMAIL_RE.sub(_REDACTED, data)
        data = _PHONE_RE.sub(_REDACTED, data)
        data = _CARD_RE.sub(_REDACTED, data)
        data = _SSN_RE.sub(_REDACTED, data)
        if data != original:
            warnings.append("String value contained sensitive patterns and was redacted.")
        return data, warnings

    return data, warnings
