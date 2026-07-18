"""Per-grant TTL validation and resolution (#203).

Extracted from :mod:`weaver_kernel.policy` to keep that module within the
AGENTS.md 300-line budget (it is already at its ratchet ceiling). The maximum
per-grant token TTL is policy configuration; :class:`DefaultPolicyEngine` stores
the raw value and delegates validation and per-capability resolution here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enums import SafetyClass
from .errors import AgentKernelError

if TYPE_CHECKING:  # pragma: no cover
    from .models import Capability

MaxTTLConfig = int | dict[SafetyClass, int] | None
"""A single TTL cap, a per-safety-class mapping, or ``None`` for no maximum."""


def validate_max_ttl_s(max_ttl_s: MaxTTLConfig) -> None:
    """Reject a non-positive ``max_ttl_s`` configuration.

    Args:
        max_ttl_s: The configured maximum TTL (scalar, per-class map, or ``None``).

    Raises:
        AgentKernelError: If any configured value is not a positive integer.
    """
    if max_ttl_s is None:
        return
    values = max_ttl_s.values() if isinstance(max_ttl_s, dict) else [max_ttl_s]
    for value in values:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise AgentKernelError(
                f"Invalid max_ttl_s: values must be positive integers, got {value!r}."
            )


def resolve_max_ttl_s(max_ttl_s: MaxTTLConfig, capability: Capability) -> int | None:
    """Return the maximum allowed TTL for *capability*, or ``None`` if uncapped.

    Args:
        max_ttl_s: The configured maximum TTL (scalar, per-class map, or ``None``).
        capability: The capability whose grant TTL is being bounded.

    Returns:
        The maximum TTL in seconds, or ``None`` when no cap applies.
    """
    if max_ttl_s is None:
        return None
    if isinstance(max_ttl_s, dict):
        return max_ttl_s.get(capability.safety_class)
    return max_ttl_s


__all__ = ["MaxTTLConfig", "validate_max_ttl_s", "resolve_max_ttl_s"]
