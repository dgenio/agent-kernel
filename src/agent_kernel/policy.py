"""Policy engine: role-based access control with confused-deputy prevention."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .enums import SafetyClass, SensitivityTag
from .errors import PolicyDenied
from .models import Capability, CapabilityRequest, PolicyDecision, Principal

logger = logging.getLogger(__name__)

# Minimum justification length for WRITE operations.
_MIN_JUSTIFICATION = 15

# Default max_rows caps.
_MAX_ROWS_USER = 50
_MAX_ROWS_SERVICE = 500

# Default rate limits per safety class: (invocations, window_seconds).
_DEFAULT_RATE_LIMITS: dict[SafetyClass, tuple[int, float]] = {
    SafetyClass.READ: (60, 60.0),
    SafetyClass.WRITE: (10, 60.0),
    SafetyClass.DESTRUCTIVE: (2, 60.0),
}

# Service role multiplier for rate limits.
_SERVICE_RATE_MULTIPLIER = 10


@dataclass(slots=True)
class _RateEntry:
    """Timestamps for a single rate-limit key."""

    timestamps: list[float]


class RateLimiter:
    """Sliding-window rate limiter using monotonic clock.

    Args:
        clock: Callable returning the current time in seconds.
            Defaults to :func:`time.monotonic`.
    """

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._windows: dict[str, _RateEntry] = defaultdict(lambda: _RateEntry(timestamps=[]))

    def check(self, key: str, limit: int, window_seconds: float) -> bool:
        """Return ``True`` if the next invocation would be within the limit.

        Prunes expired timestamps as a side-effect.

        Args:
            key: Rate-limit key (e.g. ``"principal:capability"``).
            limit: Maximum allowed invocations per window.
            window_seconds: Sliding window duration in seconds.

        Returns:
            ``True`` if under limit, ``False`` if limit would be exceeded.
        """
        now = self._clock()
        cutoff = now - window_seconds
        entry = self._windows[key]
        entry.timestamps = [t for t in entry.timestamps if t > cutoff]
        if not entry.timestamps:
            del self._windows[key]
            return True
        return len(entry.timestamps) < limit

    def record(self, key: str) -> None:
        """Record an invocation for *key*.

        Args:
            key: Rate-limit key.
        """
        self._windows[key].timestamps.append(self._clock())


class PolicyEngine(Protocol):
    """Interface for a policy engine."""

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate whether *principal* may perform *request* on *capability*.

        Args:
            request: The capability request being evaluated.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            A :class:`PolicyDecision` (allowed or denied with reason).
        """
        ...


class DefaultPolicyEngine:
    """Rule-based policy engine implementing the default access control policy.

    Rules (evaluated in order):

    1. **READ** — allowed (subject to sensitivity and row-cap rules below).
    2. **WRITE** — requires:
       - ``justification`` of at least 15 characters.
       - Principal role ``"writer"`` **or** ``"admin"``.
    3. **DESTRUCTIVE** — requires principal role ``"admin"``.
    4. **PII / PCI sensitivity** — requires the ``tenant`` attribute on the
       principal.  Enforces ``allowed_fields`` unless the principal has the
       ``pii_reader`` role.
    5. **SECRETS sensitivity** — requires principal role ``"admin"`` or
       ``"secrets_reader"`` and a justification of at least 15 characters.
    6. **max_rows** — 50 for regular users; 500 for principals with the
       ``"service"`` role.
    7. **Rate limiting** — sliding-window rate limit per
       ``(principal_id, capability_id)`` pair, with defaults by safety class.
       Principals with the ``"service"`` role get 10× the default limits.
    """

    def __init__(
        self,
        *,
        rate_limits: dict[SafetyClass, tuple[int, float]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Initialise the policy engine.

        Args:
            rate_limits: Override default rate limits per safety class.
                Each value is ``(max_invocations, window_seconds)``.
                Partial overrides are merged into the defaults so that
                unspecified safety classes retain their default limits.
            clock: Monotonic clock callable for rate-limiter.
                Defaults to :func:`time.monotonic`.
        """
        limits = dict(_DEFAULT_RATE_LIMITS)
        if rate_limits is not None:
            limits.update(rate_limits)
        self._rate_limits = limits
        self._limiter = RateLimiter(clock=clock)

    @staticmethod
    def _deny(reason: str, *, principal_id: str, capability_id: str) -> PolicyDenied:
        """Log a policy denial at WARNING and return the exception to raise."""
        logger.warning(
            "policy_denied",
            extra={
                "principal_id": principal_id,
                "capability_id": capability_id,
                "reason": reason,
            },
        )
        return PolicyDenied(reason)

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate the request against the default policy rules.

        Args:
            request: The capability request being evaluated.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            :class:`PolicyDecision` with ``allowed=True`` and any imposed
            constraints, or raises :class:`PolicyDenied`.

        Raises:
            PolicyDenied: When the request violates a policy rule.
        """
        roles = set(principal.roles)
        constraints: dict[str, Any] = dict(request.constraints)

        pid = principal.principal_id
        cid = capability.capability_id

        # ── Safety class checks ───────────────────────────────────────────────

        if capability.safety_class == SafetyClass.WRITE:
            if not (roles & {"writer", "admin"}):
                raise self._deny(
                    f"WRITE capabilities require the 'writer' or 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}.",
                    principal_id=pid,
                    capability_id=cid,
                )
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise self._deny(
                    f"WRITE capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace).",
                    principal_id=pid,
                    capability_id=cid,
                )

        elif capability.safety_class == SafetyClass.DESTRUCTIVE:
            if "admin" not in roles:
                raise self._deny(
                    f"DESTRUCTIVE capabilities require the 'admin' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}.",
                    principal_id=pid,
                    capability_id=cid,
                )
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise self._deny(
                    f"DESTRUCTIVE capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace).",
                    principal_id=pid,
                    capability_id=cid,
                )

        # ── Sensitivity checks ────────────────────────────────────────────────

        if capability.sensitivity in (SensitivityTag.PII, SensitivityTag.PCI):
            if "tenant" not in principal.attributes:
                raise self._deny(
                    f"Capability '{cid}' has "
                    f"{capability.sensitivity.value} sensitivity and requires "
                    "the principal to have a 'tenant' attribute.",
                    principal_id=pid,
                    capability_id=cid,
                )
            # Enforce allowed_fields unless the principal is a pii_reader.
            if capability.allowed_fields and "pii_reader" not in roles:
                constraints["allowed_fields"] = capability.allowed_fields

        if capability.sensitivity == SensitivityTag.SECRETS:
            if not (roles & {"admin", "secrets_reader"}):
                raise self._deny(
                    f"SECRETS capabilities require the 'admin' or 'secrets_reader' role. "
                    f"Principal '{pid}' has roles: {sorted(roles)}.",
                    principal_id=pid,
                    capability_id=cid,
                )
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise self._deny(
                    f"SECRETS capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace).",
                    principal_id=pid,
                    capability_id=cid,
                )

        # ── Row cap ───────────────────────────────────────────────────────────

        max_rows = _MAX_ROWS_SERVICE if "service" in roles else _MAX_ROWS_USER
        # Respect any tighter constraint from the request itself.
        if "max_rows" in constraints:
            try:
                requested = int(constraints["max_rows"])
            except (TypeError, ValueError) as exc:
                raise self._deny(
                    f"Invalid 'max_rows' constraint: {constraints['max_rows']!r} "
                    "is not a valid integer.",
                    principal_id=pid,
                    capability_id=cid,
                ) from exc
            constraints["max_rows"] = min(max(requested, 0), max_rows)
        else:
            constraints["max_rows"] = max_rows

        # ── Rate limiting ─────────────────────────────────────────────────

        rate_key = f"{pid}:{cid}"
        if capability.safety_class in self._rate_limits:
            limit, window = self._rate_limits[capability.safety_class]
            if "service" in roles:
                limit *= _SERVICE_RATE_MULTIPLIER
            if not self._limiter.check(rate_key, limit, window):
                raise self._deny(
                    f"Rate limit exceeded: {limit} {capability.safety_class.value} "
                    f"invocations per {window}s for principal '{pid}'",
                    principal_id=pid,
                    capability_id=cid,
                )
            self._limiter.record(rate_key)

        reason = "Request approved by DefaultPolicyEngine."
        logger.info(
            "policy_allowed",
            extra={
                "principal_id": pid,
                "capability_id": cid,
                "reason": reason,
            },
        )
        return PolicyDecision(
            allowed=True,
            reason=reason,
            constraints=constraints,
        )
