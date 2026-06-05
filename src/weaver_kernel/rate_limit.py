"""Sliding-window rate limiter used by :class:`DefaultPolicyEngine`.

Split out of :mod:`policy` to keep modules ≤ 300 lines (AGENTS.md).
The default per-safety-class limits and the service multiplier live here
because they are tightly bound to :class:`RateLimiter` semantics.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from .enums import SafetyClass

DEFAULT_RATE_LIMITS: dict[SafetyClass, tuple[int, float]] = {
    SafetyClass.READ: (60, 60.0),
    SafetyClass.WRITE: (10, 60.0),
    SafetyClass.DESTRUCTIVE: (2, 60.0),
}
"""Default rate limits per safety class: ``(invocations, window_seconds)``."""

SERVICE_RATE_MULTIPLIER = 10
"""Multiplier applied for principals with the ``service`` role."""


@dataclass(slots=True)
class _RateEntry:
    """Timestamps for a single rate-limit key."""

    timestamps: list[float]


class RateLimiter:
    """Sliding-window rate limiter using a monotonic clock.

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
        """Record an invocation for *key*."""
        self._windows[key].timestamps.append(self._clock())


__all__ = [
    "DEFAULT_RATE_LIMITS",
    "SERVICE_RATE_MULTIPLIER",
    "RateLimiter",
]
