"""Driver execution: route-plan fallback, deadlines, and fault capture.

Extracted from :mod:`._invoke` (AGENTS.md ≤ 300-line budget) so the
driver-execution concern lives in one place: trying a route plan's drivers
in order, bounding each attempt with an optional deadline, and turning
*every* fault into an auditable failed attempt.

Invariants preserved here (see ``docs/agent-context/invariants.md``):

* **I-02 (auditability).** Any exception a driver raises — ``DriverError`` or
  otherwise — is recorded as a failed attempt and surfaced to
  :func:`._invoke.perform_invoke` as ``last_error``, so the caller always
  writes a failure :class:`~weaver_kernel.models.ActionTrace` and releases the
  budget reservation (#152). A driver fault never escapes un-audited with the
  reservation leaked.
* **Bounded execution.** When the token carries an ``invoke_timeout_s``
  constraint, each driver attempt is wrapped in :func:`asyncio.wait_for`; a
  timeout becomes a synthetic ``DriverError`` so the existing fallback and
  failure-trace paths apply unchanged (#191).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..drivers.base import Driver, ExecutionContext
from ..errors import DriverError
from ..models import RawResult, RoutePlan

logger = logging.getLogger("weaver_kernel.kernel")

INVOKE_TIMEOUT_CONSTRAINT = "invoke_timeout_s"
"""Token-constraint key carrying the per-invocation deadline in seconds (#191)."""


def resolve_invoke_timeout(constraints: dict[str, Any]) -> float | None:
    """Return the per-invocation deadline in seconds, or ``None`` if unset.

    Reads the optional ``"invoke_timeout_s"`` token constraint (#191). Because
    constraints are signed into the capability token, the deadline is
    tamper-evident and bound to the grant rather than to mutable kernel state.

    Args:
        constraints: The verified token's ``constraints`` mapping.

    Returns:
        A positive ``float`` deadline, or ``None`` when no deadline applies.

    Raises:
        DriverError: If the constraint is present but not a positive number
            (booleans are rejected — ``True``/``False`` are not durations).
    """
    raw = constraints.get(INVOKE_TIMEOUT_CONSTRAINT)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
        raise DriverError(
            f"Invalid '{INVOKE_TIMEOUT_CONSTRAINT}' constraint: {raw!r} "
            f"(must be a positive number of seconds)."
        )
    return float(raw)


async def execute_with_fallback(
    drivers: dict[str, Driver],
    plan: RoutePlan,
    *,
    ctx: ExecutionContext,
    log_ctx: dict[str, str],
    timeout: float | None = None,
) -> tuple[RawResult | None, str, Exception | None, bool]:
    """Iterate the route plan's drivers until one succeeds.

    Args:
        drivers: The kernel's registered driver map.
        plan: The router-resolved route plan to walk in order.
        ctx: The execution context handed to each driver.
        log_ctx: Structured logging fields propagated to each log record.
        timeout: Optional per-attempt deadline in seconds (#191). When set, a
            driver attempt exceeding it is converted to a synthetic
            ``DriverError`` and treated as a failed attempt.

    Returns:
        ``(raw_result, driver_id, last_error, fell_back)``. ``raw_result`` is
        ``None`` if every driver failed; ``fell_back`` is ``True`` when at least
        one earlier driver raised before the one that ultimately ran (or before
        all-failed), so callers can count fallback activations. A route entry
        whose driver is unregistered (``drivers.get(driver_id) is None``) is
        skipped silently and does **not** set ``fell_back``.

        A ``DriverError`` *and* any other exception a driver raises both count
        as a failed attempt (#152); the latter is preserved as ``last_error``
        so the caller still records a failure trace and releases the budget
        rather than letting it escape un-audited.
    """
    last_error: Exception | None = None
    failed_attempts = 0
    for driver_id in plan.driver_ids:
        driver = drivers.get(driver_id)
        if driver is None:
            continue
        try:
            if timeout is None:
                raw_result = await driver.execute(ctx)
            else:
                raw_result = await asyncio.wait_for(driver.execute(ctx), timeout)
            logger.debug("driver_success", extra={**log_ctx, "driver_id": driver_id})
            return raw_result, driver_id, None, failed_attempts > 0
        except asyncio.TimeoutError:
            logger.warning(
                "driver_timeout",
                extra={**log_ctx, "driver_id": driver_id, "timeout_s": timeout},
            )
            last_error = DriverError(
                f"Driver '{driver_id}' timed out after {timeout}s "
                f"for capability '{ctx.capability_id}'."
            )
            failed_attempts += 1
            continue
        except DriverError as exc:
            logger.warning(
                "driver_failure",
                extra={**log_ctx, "driver_id": driver_id, "error": str(exc)},
            )
            last_error = exc
            failed_attempts += 1
            continue
        except Exception as exc:
            # I-02: a driver raising an *unexpected* (non-DriverError) exception
            # must still be audited. Capture it as a failed attempt so
            # perform_invoke records a failure trace and releases the
            # reservation (#152) instead of the exception escaping un-traced
            # with the budget leaked.
            logger.warning(
                "driver_failure_unexpected",
                extra={
                    **log_ctx,
                    "driver_id": driver_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            last_error = exc
            failed_attempts += 1
            continue
    return None, "", last_error, failed_attempts > 0


__all__ = ["execute_with_fallback", "resolve_invoke_timeout", "INVOKE_TIMEOUT_CONSTRAINT"]
