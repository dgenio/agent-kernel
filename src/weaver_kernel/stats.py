"""In-process kernel metrics counters (#179).

A dependency-free, lock-guarded set of aggregate counters that answers cheap
operational questions — "is the firewall actually redacting anything?", "how
often are budgets downgrading responses?", "what's my denial rate by reason?" —
without exporting the full audit trail. This is the "counters first, exporters
second" layering: the counters work everywhere, and the OpenTelemetry exporter
(:mod:`weaver_kernel.otel`, #125) can read them as gauges where that extra is
installed.

Counters are *aggregates*, never a substitute for :class:`ActionTrace` records:
they hold no principal/capability detail, only totals. Streaming invocations are
counted once per stream; dry runs are not counted (they execute no driver and
record no trace).

Usage::

    snapshot = kernel.stats          # immutable StatsSnapshot
    print(snapshot.redaction_events, snapshot.denials_by_reason)
    kernel.reset_stats()             # zero the live counters
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class StatsSnapshot:
    """Immutable point-in-time copy of the kernel's counters.

    Returned by :meth:`KernelStats.snapshot` (and by ``Kernel.stats``). Integer
    fields are plain counts; :attr:`denials_by_reason` is a read-only mapping of
    stable :class:`~weaver_kernel.policy_reasons.DenialReason` value → count.
    """

    grants: int = 0
    """Successful capability grants (a signed token was issued)."""

    denials: int = 0
    """Grant attempts rejected by the policy engine (``PolicyDenied``)."""

    invocations: int = 0
    """Capability invocations that produced a Frame (one per stream)."""

    invocation_failures: int = 0
    """Invocations where every routed driver failed (a failure trace was recorded)."""

    fallback_activations: int = 0
    """Invocations where the first routed driver failed and a later one was tried."""

    redaction_events: int = 0
    """Invocations whose firewalled Frame carried at least one redaction warning."""

    budget_downgrades: int = 0
    """Invocations whose response mode was downgraded (admin gate or budget pressure)."""

    handle_stores: int = 0
    """Full-result handles created (one per non-``raw`` invocation that stored data)."""

    expansions: int = 0
    """Handle-expansion data-access events served."""

    denials_by_reason: Mapping[str, int] = field(default_factory=dict)
    """Denial counts keyed by stable reason code (``None`` codes counted as ``"unknown"``)."""


class KernelStats:
    """Live, thread-safe collector behind ``Kernel.stats``.

    Increment methods are called at the kernel's natural choke points (grant,
    invoke, fallback, firewall, handle store/expand). Each increment is guarded
    by a single lock; contention is negligible at counter granularity.
    :meth:`snapshot` returns an immutable :class:`StatsSnapshot`; :meth:`reset`
    zeroes every counter.
    """

    __slots__ = (
        "_lock",
        "_grants",
        "_denials",
        "_invocations",
        "_invocation_failures",
        "_fallback_activations",
        "_redaction_events",
        "_budget_downgrades",
        "_handle_stores",
        "_expansions",
        "_denials_by_reason",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants = 0
        self._denials = 0
        self._invocations = 0
        self._invocation_failures = 0
        self._fallback_activations = 0
        self._redaction_events = 0
        self._budget_downgrades = 0
        self._handle_stores = 0
        self._expansions = 0
        self._denials_by_reason: dict[str, int] = {}

    def on_grant(self) -> None:
        """Count a successful grant."""
        with self._lock:
            self._grants += 1

    def on_denial(self, reason_code: str | None) -> None:
        """Count a policy denial, bucketed by stable reason code."""
        key = reason_code or "unknown"
        with self._lock:
            self._denials += 1
            self._denials_by_reason[key] = self._denials_by_reason.get(key, 0) + 1

    def on_invocation(
        self, *, failed: bool, fallback: bool, redacted: bool, downgraded: bool
    ) -> None:
        """Count one invocation outcome and its firewall/routing side effects.

        Args:
            failed: Every routed driver failed (a failure trace was recorded).
            fallback: A driver other than the first in the route plan served it.
            redacted: The resulting Frame carried at least one redaction warning.
            downgraded: The effective response mode differed from the requested one.
        """
        with self._lock:
            self._invocations += 1
            if failed:
                self._invocation_failures += 1
            if fallback:
                self._fallback_activations += 1
            if redacted:
                self._redaction_events += 1
            if downgraded:
                self._budget_downgrades += 1

    def on_handle_store(self) -> None:
        """Count a full-result handle creation."""
        with self._lock:
            self._handle_stores += 1

    def on_expansion(self) -> None:
        """Count a handle-expansion data-access event."""
        with self._lock:
            self._expansions += 1

    def snapshot(self) -> StatsSnapshot:
        """Return an immutable copy of the current counters."""
        with self._lock:
            return StatsSnapshot(
                grants=self._grants,
                denials=self._denials,
                invocations=self._invocations,
                invocation_failures=self._invocation_failures,
                fallback_activations=self._fallback_activations,
                redaction_events=self._redaction_events,
                budget_downgrades=self._budget_downgrades,
                handle_stores=self._handle_stores,
                expansions=self._expansions,
                denials_by_reason=MappingProxyType(dict(self._denials_by_reason)),
            )

    def reset(self) -> None:
        """Zero every counter."""
        with self._lock:
            self._grants = 0
            self._denials = 0
            self._invocations = 0
            self._invocation_failures = 0
            self._fallback_activations = 0
            self._redaction_events = 0
            self._budget_downgrades = 0
            self._handle_stores = 0
            self._expansions = 0
            self._denials_by_reason.clear()


__all__ = ["KernelStats", "StatsSnapshot"]
