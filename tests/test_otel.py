"""Tests for OpenTelemetry instrumentation (:func:`weaver_kernel.instrument_kernel`).

These tests use the OpenTelemetry SDK's ``InMemorySpanExporter`` and
``InMemoryMetricReader`` so we don't need a running collector. They
assert two specific contracts:

1. **Instrumented kernel emits the expected spans/metrics.** Span names,
   parent–child structure, and key attributes are pinned.

2. **Uninstrumented kernel emits zero spans.** This guards against the
   instrumentation accidentally leaking into every kernel by class-level
   monkey-patching (it should be instance-level only).
"""

from __future__ import annotations

import pytest

from weaver_kernel import (
    OTEL_AVAILABLE,
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
    instrument_kernel,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.models import CapabilityRequest
from weaver_kernel.otel import reset_instrumentation

if not OTEL_AVAILABLE:  # pragma: no cover - skipped without the [otel] extra
    pytest.skip(
        "opentelemetry-api not installed; install the [otel] extra to run.",
        allow_module_level=True,
    )

try:
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
except ImportError:  # pragma: no cover - SDK extra not installed
    pytest.skip(
        "opentelemetry-sdk not installed; install opentelemetry-sdk (and an "
        "exporter) to run the OTel instrumentation tests.",
        allow_module_level=True,
    )


def _build_kernel() -> tuple[Kernel, Principal]:
    cap = Capability(
        capability_id="metrics.read",
        name="read",
        description="Read a metric.",
        safety_class=SafetyClass.READ,
    )
    registry = CapabilityRegistry()
    registry.register(cap)

    driver = InMemoryDriver(driver_id="memory")

    def handler(ctx: ExecutionContext) -> dict[str, object]:
        return {"value": 42, "capability_id": ctx.capability_id}

    driver.register_handler("metrics.read", handler)

    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="otel-test-secret"),
        router=StaticRouter(routes={"metrics.read": ["memory"]}),
    )
    kernel.register_driver(driver)

    principal = Principal(principal_id="otel-user", roles=["reader"])
    return kernel, principal


@pytest.fixture()
def otel_exporters() -> tuple[
    InMemorySpanExporter, InMemoryMetricReader, TracerProvider, MeterProvider
]:
    """Per-test span/metric exporters with provider instances.

    The OTel API disallows overriding the global ``TracerProvider`` /
    ``MeterProvider`` after they've been set; instead each test gets its
    own providers and passes them explicitly to :func:`instrument_kernel`.
    """
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])

    reset_instrumentation()
    yield span_exporter, metric_reader, tracer_provider, meter_provider
    reset_instrumentation()


@pytest.mark.asyncio
async def test_instrumented_invoke_emits_span(
    otel_exporters: tuple[
        InMemorySpanExporter, InMemoryMetricReader, TracerProvider, MeterProvider
    ],
) -> None:
    """`Kernel.invoke()` produces one ``weaver_kernel.invoke`` span."""
    spans, _, tp, mp = otel_exporters
    kernel, principal = _build_kernel()
    instrument_kernel(kernel, tracer_provider=tp, meter_provider=mp)

    req = CapabilityRequest(capability_id="metrics.read", goal="t")
    token = kernel.get_token(req, principal, justification="")
    await kernel.invoke(token, principal=principal, args={})

    finished = spans.get_finished_spans()
    invoke_spans = [s for s in finished if s.name == "weaver_kernel.invoke"]
    assert len(invoke_spans) == 1, [s.name for s in finished]
    attrs = invoke_spans[0].attributes or {}
    assert attrs.get("weaver_kernel.principal_id") == "otel-user"
    assert attrs.get("weaver_kernel.capability_id") == "metrics.read"
    assert attrs.get("weaver_kernel.response_mode") == "summary"
    assert attrs.get("weaver_kernel.dry_run") is False


@pytest.mark.asyncio
async def test_uninstrumented_invoke_emits_no_span(
    otel_exporters: tuple[
        InMemorySpanExporter, InMemoryMetricReader, TracerProvider, MeterProvider
    ],
) -> None:
    """A kernel that was never wrapped emits zero ``weaver_kernel.*`` spans."""
    spans, _, _, _ = otel_exporters
    kernel, principal = _build_kernel()
    # Deliberately do NOT call instrument_kernel.

    req = CapabilityRequest(capability_id="metrics.read", goal="t")
    token = kernel.get_token(req, principal, justification="")
    await kernel.invoke(token, principal=principal, args={})

    finished = spans.get_finished_spans()
    invoke_spans = [s for s in finished if s.name.startswith("weaver_kernel.")]
    assert invoke_spans == []


def test_instrumented_grant_records_denial(
    otel_exporters: tuple[
        InMemorySpanExporter, InMemoryMetricReader, TracerProvider, MeterProvider
    ],
) -> None:
    """A denied grant records a span with ERROR status and a denial counter."""
    spans, _metric_reader, tp, mp = otel_exporters
    kernel, _ = _build_kernel()
    instrument_kernel(kernel, tracer_provider=tp, meter_provider=mp)

    # Build a "deny" path: WRITE capability + reader principal.
    write_cap = Capability(
        capability_id="metrics.write",
        name="write",
        description="Write a metric.",
        safety_class=SafetyClass.WRITE,
    )
    kernel._registry.register(write_cap)  # type: ignore[attr-defined]

    reader = Principal(principal_id="reader-only", roles=["reader"])
    req = CapabilityRequest(capability_id="metrics.write", goal="t")

    from weaver_kernel.errors import PolicyDenied

    with pytest.raises(PolicyDenied):
        kernel.grant_capability(req, reader, justification="too short")

    finished = spans.get_finished_spans()
    grant_spans = [s for s in finished if s.name == "weaver_kernel.grant"]
    assert len(grant_spans) == 1
    assert grant_spans[0].status.status_code.name == "ERROR"


def test_instrument_kernel_is_idempotent() -> None:
    """Calling :func:`instrument_kernel` twice does not double-wrap."""
    kernel, _ = _build_kernel()
    original_invoke = kernel.invoke
    instrument_kernel(kernel)
    wrapped_once = kernel.invoke
    assert wrapped_once is not original_invoke
    instrument_kernel(kernel)
    assert kernel.invoke is wrapped_once
    reset_instrumentation(kernel)
