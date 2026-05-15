"""Cross-invocation session-level budget manager.

A :class:`BudgetManager` tracks cumulative token usage across multiple
:meth:`~agent_kernel.Kernel.invoke` calls and suggests
:class:`~agent_kernel.models.ResponseMode` escalation as the remaining budget
shrinks. The manager is optional — a :class:`~agent_kernel.Kernel`
constructed without one behaves identically to earlier versions of the
library.

This module is the implementation of issue #44.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from ..errors import BudgetConfigError, BudgetExhausted
from ..models import ResponseMode
from .token_counting import TokenCounter, default_token_counter

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _BudgetState:
    """Internal mutable state for :class:`BudgetManager`."""

    total: int
    used: int
    reserved: int


class BudgetManager:
    """Tracks cumulative token usage across invocations within a session.

    When attached to a :class:`~agent_kernel.Kernel` via the
    ``budget_manager`` constructor parameter, the kernel calls
    :meth:`allocate` before every invocation to reserve a slice of the
    remaining budget and :meth:`record_usage` after the firewall has
    produced a Frame to reconcile actual consumption. Once the remaining
    budget shrinks, the kernel consults :meth:`suggested_mode` to escalate
    the requested response mode to a more aggressive summarisation tier.

    Concurrency: :meth:`allocate`, :meth:`record_usage`, and :meth:`release`
    are serialised behind an internal :class:`asyncio.Lock` so concurrent
    invocations from the same kernel see consistent budget state.

    Example::

        manager = BudgetManager(total_budget=100_000)
        kernel = Kernel(registry, budget_manager=manager)
        frame = await kernel.invoke(token, principal=p, args={})  # consumes
        assert manager.remaining < 100_000
    """

    __slots__ = ("_state", "_lock", "_counter", "_default_request")

    def __init__(
        self,
        total_budget: int = 100_000,
        *,
        token_counter: TokenCounter | None = None,
        default_request: int = 4_000,
    ) -> None:
        """Initialise a :class:`BudgetManager`.

        Args:
            total_budget: Total token budget for the session. Must be > 0.
            token_counter: Optional custom :class:`TokenCounter`. Defaults
                to :func:`default_token_counter` (chars/4 approximation).
            default_request: Tokens to reserve per :meth:`allocate` call
                when the caller does not pass an explicit ``requested``
                amount. Must be > 0.

        Raises:
            BudgetConfigError: If ``total_budget`` or ``default_request``
                is non-positive.
        """
        if total_budget <= 0:
            raise BudgetConfigError("total_budget must be positive")
        if default_request <= 0:
            raise BudgetConfigError("default_request must be positive")
        self._state = _BudgetState(total=total_budget, used=0, reserved=0)
        self._lock = asyncio.Lock()
        self._counter: TokenCounter = token_counter or default_token_counter
        self._default_request = default_request

    # ── Read-only properties ──────────────────────────────────────────────────

    @property
    def total_budget(self) -> int:
        """The total session budget configured at construction."""
        return self._state.total

    @property
    def remaining(self) -> int:
        """Budget remaining after accounting for committed *and* reserved use.

        Reservations are subtracted so that two concurrent :meth:`allocate`
        calls cannot both believe the same budget slice is free.
        """
        return max(0, self._state.total - self._state.used - self._state.reserved)

    @property
    def used(self) -> int:
        """Tokens already committed via :meth:`record_usage`."""
        return self._state.used

    @property
    def usage_fraction(self) -> float:
        """Fraction of the total budget already committed (``used / total``).

        Reservations are *not* counted here — only committed usage. The
        value is always in ``[0.0, 1.0]``.
        """
        if self._state.total == 0:
            return 1.0
        return min(1.0, self._state.used / self._state.total)

    # ── Allocation / recording ────────────────────────────────────────────────

    async def allocate(self, requested: int | None = None) -> int:
        """Reserve a budget slice for an upcoming invocation.

        Args:
            requested: Tokens the caller would like to spend. ``None`` uses
                the manager's ``default_request``. Negative values are
                rejected.

        Returns:
            The number of tokens actually reserved
            (``min(requested, remaining)``). May be less than ``requested``
            when the budget is nearly exhausted but non-zero.

        Raises:
            BudgetExhausted: If no budget remains at all.
            BudgetConfigError: If ``requested`` is negative.
        """
        if requested is not None and requested < 0:
            raise BudgetConfigError("requested must be non-negative")
        async with self._lock:
            if self.remaining <= 0:
                raise BudgetExhausted(
                    f"Session budget exhausted: used {self._state.used} of "
                    f"{self._state.total} tokens (no budget remaining)."
                )
            want = self._default_request if requested is None else requested
            granted = min(want, self.remaining)
            self._state.reserved += granted
            logger.debug(
                "budget_allocate",
                extra={
                    "requested": want,
                    "granted": granted,
                    "remaining": self.remaining,
                    "used": self._state.used,
                },
            )
            return granted

    async def record_usage(self, actual: int, *, reserved: int | None = None) -> None:
        """Reconcile a completed invocation against a prior reservation.

        Args:
            actual: Actual tokens consumed (computed via
                :meth:`count_tokens` on the Frame payload). Negative values
                are rejected.
            reserved: The value previously returned by :meth:`allocate`. If
                omitted, the reservation pool is left untouched and only
                ``actual`` is added to ``used``.

        Raises:
            BudgetConfigError: If ``actual`` or ``reserved`` is negative.
        """
        if actual < 0:
            raise BudgetConfigError("actual must be non-negative")
        if reserved is not None and reserved < 0:
            raise BudgetConfigError("reserved must be non-negative")
        async with self._lock:
            if reserved is not None:
                self._state.reserved = max(0, self._state.reserved - reserved)
            self._state.used = min(self._state.total, self._state.used + actual)
            logger.debug(
                "budget_record",
                extra={
                    "actual": actual,
                    "reserved_released": reserved or 0,
                    "remaining": self.remaining,
                    "used": self._state.used,
                },
            )

    async def release(self, reserved: int) -> None:
        """Release a reservation without recording any usage.

        Called when an invocation fails before the firewall runs (for
        example the driver raised :class:`~agent_kernel.errors.DriverError`
        or the firewall itself raised).

        Args:
            reserved: The amount previously returned by :meth:`allocate`.

        Raises:
            BudgetConfigError: If ``reserved`` is negative.
        """
        if reserved < 0:
            raise BudgetConfigError("reserved must be non-negative")
        async with self._lock:
            self._state.reserved = max(0, self._state.reserved - reserved)

    # ── Counting / mode suggestion ────────────────────────────────────────────

    def count_tokens(self, value: Any) -> int:
        """Count tokens for *value* using the configured :class:`TokenCounter`."""
        return self._counter(value)

    def suggested_mode(self, requested: ResponseMode) -> ResponseMode:
        """Suggest a response mode based on remaining budget.

        Escalation table (issue #44). Boundaries land in the more-conservative
        tier, so 50% exactly downgrades raw and 20% exactly floors at summary:

        =================  ==============================================
        Budget remaining   Suggested mode
        =================  ==============================================
        > 50%              Caller's requested mode
        20% – 50%          ``table`` (if caller requested ``raw``)
        5% – 20% (≥ 5%)    ``summary`` (or stricter if already requested)
        < 5%               ``handle_only``
        =================  ==============================================

        The suggestion never *relaxes* a stricter caller-requested mode —
        if the caller asked for ``handle_only`` the result is always
        ``handle_only``. ``raw`` is downgraded as soon as remaining drops
        to 50% or below because raw payloads are unbounded and the
        cross-session budget cannot accommodate them.

        Args:
            requested: Mode the caller asked for.

        Returns:
            Mode the kernel should actually use for the upcoming
            invocation. Deterministic — no randomness.
        """
        if self._state.total == 0:
            return "handle_only"
        fraction_remaining = self.remaining / self._state.total
        if fraction_remaining < 0.05:
            return "handle_only"
        if fraction_remaining <= 0.20:
            return _stricter(requested, "summary")
        if fraction_remaining <= 0.50:
            if requested == "raw":
                return "table"
            return requested
        return requested


# ── Internal helpers ──────────────────────────────────────────────────────────


_MODE_RANK: dict[ResponseMode, int] = {
    "raw": 0,
    "table": 1,
    "summary": 2,
    "handle_only": 3,
}


def _stricter(requested: ResponseMode, floor: ResponseMode) -> ResponseMode:
    """Return whichever of *requested* and *floor* is stricter (higher rank)."""
    return requested if _MODE_RANK[requested] >= _MODE_RANK[floor] else floor
