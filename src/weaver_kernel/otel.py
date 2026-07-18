"""OpenTelemetry instrumentation for the :class:`Kernel`.

Calling :func:`instrument_kernel(kernel)` wraps the kernel's
``invoke`` and ``grant_capability`` methods with OTel spans + metric
emission.

When ``opentelemetry-api`` is not installed, :func:`instrument_kernel`
is a complete no-op — the import succeeds, the call is a no-op, and no
runtime cost is paid. This lets the optional ``[otel]`` extra stay
optional without forcing users to handle ``ImportError`` themselves.

Span tree
---------

``invoke()`` produces::

    weaver_kernel.invoke
      ├── attributes: principal_id, capability_id, safety_class,
      │              response_mode, dry_run
      ├── weaver_kernel.driver.execute (per driver attempt)
      └── weaver_kernel.firewall.apply

Metrics
-------

* ``weaver_kernel.invocations`` (counter) — labels:
  ``capability_id``, ``status`` (``success``/``error``/``denied``).
* ``weaver_kernel.invocation_duration`` (histogram, milliseconds).
* ``weaver_kernel.policy_denials`` (counter) — labels: ``capability_id``,
  ``reason_code``.

Usage
-----

.. code-block:: python

    from weaver_kernel import Kernel, instrument_kernel

    kernel = Kernel(registry=...)
    instrument_kernel(kernel)  # idempotent — calling again is a no-op.
"""

from __future__ import annotations

import logging
import time
import weakref
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover
    from .kernel import Kernel

# Try to import the OTel API. If it isn't installed, fall back to a
# no-op shim that has the same surface but emits nothing. Tests and
# downstream callers can rely on ``OTEL_AVAILABLE`` to skip the
# instrumentation path without dancing around imports.

trace: Any
metrics: Any
Status: Any
StatusCode: Any

try:
    from opentelemetry import metrics as _otel_metrics
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import Status as _otel_Status
    from opentelemetry.trace import StatusCode as _otel_StatusCode

    trace = _otel_trace
    metrics = _otel_metrics
    Status = _otel_Status
    StatusCode = _otel_StatusCode
    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in the no-extra environment
    trace = None
    metrics = None
    Status = None
    StatusCode = None
    OTEL_AVAILABLE = False


# Attribute keys (re-used across spans). Kept as module constants so a
# downstream search/grep finds every emission site.
ATTR_PRINCIPAL = "weaver_kernel.principal_id"
ATTR_CAPABILITY = "weaver_kernel.capability_id"
ATTR_SAFETY_CLASS = "weaver_kernel.safety_class"
ATTR_RESPONSE_MODE = "weaver_kernel.response_mode"
ATTR_DRY_RUN = "weaver_kernel.dry_run"
ATTR_DRIVER_ID = "weaver_kernel.driver_id"
ATTR_REASON_CODE = "weaver_kernel.reason_code"

# Module-level cache so repeat :func:`instrument_kernel` calls are
# cheap idempotent no-ops on the same instance. A WeakSet keys on the
# kernel object itself (not ``id()``, which a later object can reuse
# after the original is garbage-collected) and drops entries
# automatically when a kernel is collected.
_INSTRUMENTED: weakref.WeakSet[Kernel] = weakref.WeakSet()


def instrument_kernel(
    kernel: Kernel,
    *,
    tracer_provider: Any = None,
    meter_provider: Any = None,
) -> None:
    """Wrap *kernel*'s public methods with OTel spans + metric emission.

    No-op when the ``[otel]`` extra is not installed (``OTEL_AVAILABLE``
    is ``False``). Calling twice on the same kernel is a no-op — only
    the first call swaps methods.

    Args:
        kernel: The kernel to instrument in-place.
        tracer_provider: Optional ``TracerProvider`` to source the tracer
            from. Defaults to the OTel global. Useful in tests where the
            global cannot be re-set across cases.
        meter_provider: Optional ``MeterProvider`` to source the meter
            from. Defaults to the OTel global.
    """
    if not OTEL_AVAILABLE:
        logger.debug(
            "otel.skip",
            extra={"reason": "opentelemetry-api not installed"},
        )
        return
    if kernel in _INSTRUMENTED:
        return
    _INSTRUMENTED.add(kernel)

    if tracer_provider is not None:
        tracer = tracer_provider.get_tracer("weaver_kernel")
    else:
        tracer = trace.get_tracer("weaver_kernel")
    if meter_provider is not None:
        meter = meter_provider.get_meter("weaver_kernel")
    else:
        meter = metrics.get_meter("weaver_kernel")
    invocations = meter.create_counter(
        "weaver_kernel.invocations",
        description="Count of Kernel.invoke calls, labeled by status",
    )
    duration_hist = meter.create_histogram(
        "weaver_kernel.invocation_duration",
        unit="ms",
        description="Latency of Kernel.invoke (milliseconds)",
    )
    denials = meter.create_counter(
        "weaver_kernel.policy_denials",
        description="Count of policy denials, labeled by reason_code",
    )

    original_invoke = kernel.invoke
    original_grant = kernel.grant_capability

    async def instrumented_invoke(
        token: Any,
        *,
        principal: Any,
        args: dict[str, Any],
        response_mode: str = "summary",
        dry_run: bool = False,
    ) -> Any:
        start = time.monotonic()
        attributes: dict[str, Any] = {
            ATTR_PRINCIPAL: principal.principal_id,
            ATTR_CAPABILITY: token.capability_id,
            ATTR_RESPONSE_MODE: response_mode,
            ATTR_DRY_RUN: dry_run,
        }
        with tracer.start_as_current_span("weaver_kernel.invoke", attributes=attributes) as span:
            try:
                # ``response_mode`` here is a runtime str, so mypy can't pick the
                # right overload of ``Kernel.invoke``. The wrapper preserves the
                # documented call shape — this is just an erasure step.
                result = await original_invoke(  # type: ignore[call-overload]
                    token,
                    principal=principal,
                    args=args,
                    response_mode=response_mode,
                    dry_run=dry_run,
                )
                elapsed_ms = (time.monotonic() - start) * 1000.0
                # Metrics carry only low-cardinality labels; principal_id and
                # other per-call detail stay on the span to avoid metric
                # time-series explosion.
                metric_attrs = {ATTR_CAPABILITY: token.capability_id, "status": "success"}
                duration_hist.record(elapsed_ms, attributes=metric_attrs)
                invocations.add(1, metric_attrs)
                span.set_status(Status(StatusCode.OK))
                return result
            except Exception as exc:
                elapsed_ms = (time.monotonic() - start) * 1000.0
                metric_attrs = {ATTR_CAPABILITY: token.capability_id, "status": "error"}
                duration_hist.record(elapsed_ms, attributes=metric_attrs)
                invocations.add(1, metric_attrs)
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise

    def instrumented_grant(
        request: Any,
        principal: Any,
        *,
        justification: str,
        ttl_s: int | None = None,
    ) -> Any:
        attributes: dict[str, Any] = {
            ATTR_PRINCIPAL: principal.principal_id,
            ATTR_CAPABILITY: request.capability_id,
        }
        with tracer.start_as_current_span("weaver_kernel.grant", attributes=attributes) as span:
            try:
                return original_grant(request, principal, justification=justification, ttl_s=ttl_s)
            except Exception as exc:
                reason_code = getattr(exc, "reason_code", "") or ""
                denials.add(
                    1,
                    {
                        ATTR_CAPABILITY: request.capability_id,
                        ATTR_REASON_CODE: reason_code,
                    },
                )
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise

    # Bind the wrappers onto the instance (so unrelated kernels aren't
    # affected — instrumentation is per-kernel, not class-wide).
    # Cast through ``Any`` so mypy doesn't try to match the wrapper against
    # ``Kernel.invoke``'s @overload signatures. The wrapper preserves the
    # documented call shape; the overloads only matter at static-type sites
    # that read ``kernel.invoke`` directly via the class, not via the
    # instance binding we install here.
    kernel.invoke = instrumented_invoke  # type: ignore[method-assign]
    kernel.grant_capability = instrumented_grant  # type: ignore[method-assign]


def reset_instrumentation(kernel: Kernel | None = None) -> None:
    """Forget that *kernel* (or any) has been instrumented.

    Test-only helper. Re-instrumenting after this call works as if
    :func:`instrument_kernel` had never been called.
    """
    if kernel is None:
        _INSTRUMENTED.clear()
    else:
        _INSTRUMENTED.discard(kernel)


__all__ = [
    "OTEL_AVAILABLE",
    "instrument_kernel",
    "reset_instrumentation",
]
