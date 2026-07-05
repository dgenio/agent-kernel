"""Grant-TTL validation for :class:`~weaver_kernel.DefaultPolicyEngine` (#203).

Split out of :mod:`policy` to keep it within its ratchet ceiling (AGENTS.md),
the same way :mod:`rate_limit` was. Pure and stateless: the caller
(:meth:`~weaver_kernel.DefaultPolicyEngine.resolve_ttl`) turns a violation
into a logged, raised :class:`~weaver_kernel.PolicyDenied` — this module only
decides *whether* one occurred.
"""

from __future__ import annotations

from typing import NamedTuple

from .enums import SafetyClass
from .policy_reasons import DenialReason


class TtlViolation(NamedTuple):
    """Why a requested grant TTL was rejected."""

    message: str
    reason_code: str


def check_ttl(
    ttl_s: float | None,
    *,
    max_ttl_s: dict[SafetyClass, float] | None,
    safety_class: SafetyClass,
) -> TtlViolation | None:
    """Validate a requested grant TTL against a per-safety-class maximum.

    Args:
        ttl_s: The caller-requested TTL in seconds, or ``None`` (never a
            violation — the token provider's own default applies).
        max_ttl_s: Per-safety-class ceiling; ``None`` or a missing entry for
            *safety_class* means no maximum is configured.
        safety_class: The safety class of the capability being granted.

    Returns:
        A :class:`TtlViolation` describing the problem, or ``None`` if
        *ttl_s* is acceptable.
    """
    if ttl_s is None:
        return None
    if ttl_s <= 0:
        return TtlViolation(
            f"Requested TTL {ttl_s}s must be positive.",
            str(DenialReason.INVALID_CONSTRAINT),
        )
    limit = max_ttl_s.get(safety_class) if max_ttl_s else None
    if limit is not None and ttl_s > limit:
        return TtlViolation(
            f"Requested TTL {ttl_s}s exceeds the {limit}s maximum for "
            f"{safety_class.value} capabilities.",
            str(DenialReason.TTL_EXCEEDS_MAX),
        )
    return None


__all__ = ["TtlViolation", "check_ttl"]
