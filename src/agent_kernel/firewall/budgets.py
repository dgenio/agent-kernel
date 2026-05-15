"""Budgets, token counting, and cross-invocation budget management.

This module provides three things:

- :class:`Budgets` — per-invocation firewall budget caps (row/field/char/depth).
- :class:`TokenCounter` — pluggable protocol for approximating token cost of a
  value (default: ``len(json.dumps(...)) // 4``).
- :class:`BudgetManager` — cumulative session-level budget tracker that
  records token usage across multiple :meth:`~agent_kernel.Kernel.invoke`
  calls and suggests response-mode escalation as the remaining budget shrinks.

The :class:`Budgets` dataclass is unchanged from earlier versions; the new
:class:`BudgetManager` is the implementation of issue #44.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from ..errors import BudgetExhausted
from ..models import ResponseMode

logger = logging.getLogger(__name__)


# ── Per-invocation budgets ────────────────────────────────────────────────────


@dataclass(slots=True)
class Budgets:
    """Budget constraints enforced by the context firewall.

    Attributes:
        max_rows: Maximum number of rows to include in a table preview.
        max_fields: Maximum number of fields per row.
        max_chars: Maximum total characters in the frame output.
        max_depth: Maximum nesting depth when traversing dict/list values.
    """

    max_rows: int = 50
    max_fields: int = 20
    max_chars: int = 4000
    max_depth: int = 3


# ── Token counting ────────────────────────────────────────────────────────────


class TokenCounter(Protocol):
    """Approximates the token cost of an arbitrary value.

    Implementations must be deterministic and side-effect-free. The default
    implementation, :func:`default_token_counter`, uses a character-based
    approximation (``len(json.dumps(value, default=str)) // 4``) that needs
    no external dependencies. For more accurate counting, plug in a custom
    counter (for example, one that calls ``tiktoken.encoding_for_model``).
    """

    def __call__(self, value: Any) -> int: ...


def default_token_counter(value: Any) -> int:
    """Character-based token approximation (``chars // 4``).

    Args:
        value: Any JSON-serialisable value. Non-serialisable values fall back
            to ``str(value)``.

    Returns:
        A non-negative integer approximating the token count.
    """
    if value is None:
        return 0
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return max(0, len(text) // 4)


# ── Cross-invocation budget manager ───────────────────────────────────────────


@dataclass(slots=True)
class _BudgetState:
    """Internal mutable state for :class:`BudgetManager`.

    Kept separate so :class:`BudgetManager` can stay slots-friendly while
    holding an :class:`asyncio.Lock`.
    """

    total: int
    used: int
    reserved: int


class BudgetManager:
    """Tracks cumulative token usage across invocations within a session.

    A :class:`BudgetManager` is optional. When attached to a
    :class:`~agent_kernel.Kernel`, the kernel calls :meth:`allocate` before
    every invocation to reserve a slice of the remaining budget and
    :meth:`record_usage` after the firewall has produced a Frame to
    reconcile actual consumption. Once the remaining budget shrinks, the
    kernel consults :meth:`suggested_mode` to escalate the requested
    response mode to a more aggressive summarisation tier.

    Concurrency: :meth:`allocate` and :meth:`record_usage` are serialised
    behind an internal :class:`asyncio.Lock` so concurrent invocations from
    the same kernel see consistent budget state.

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
            ValueError: If ``total_budget`` or ``default_request`` is
                non-positive.
        """
        if total_budget <= 0:
            raise ValueError("total_budget must be positive")
        if default_request <= 0:
            raise ValueError("default_request must be positive")
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
            ValueError: If ``requested`` is negative.
        """
        if requested is not None and requested < 0:
            raise ValueError("requested must be non-negative")
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
            ValueError: If ``actual`` or ``reserved`` is negative.
        """
        if actual < 0:
            raise ValueError("actual must be non-negative")
        if reserved is not None and reserved < 0:
            raise ValueError("reserved must be non-negative")
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

        Called when an invocation fails before the firewall runs (e.g. the
        driver raised :class:`~agent_kernel.errors.DriverError`).

        Args:
            reserved: The amount previously returned by :meth:`allocate`.

        Raises:
            ValueError: If ``reserved`` is negative.
        """
        if reserved < 0:
            raise ValueError("reserved must be non-negative")
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
        # Boundaries land in the more-conservative tier: at exactly 50%
        # remaining, raw is downgraded; at exactly 20%, the floor is summary;
        # only when remaining drops *below* 5% does handle_only take over.
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
