"""trace_export_demo.py — export action traces for downstream analysis (#94).

The written contract lives in ``docs/trace_export.md``. This script is the
runnable companion. It shows how to turn the kernel's audit trail into a
stable, redaction-safe JSON shape that an external tool (for example a
LessonWeaver-style lesson-extraction layer) can consume without depending on
agent-kernel internals.

The demo records two invocations so the export covers both outcomes the
contract distinguishes:

  1. ``billing.list_invoices`` — a normal READ that **succeeds**.
  2. ``billing.flaky_report`` — a READ whose driver **fails**, producing a
     ``status: "failed"`` trace (a *denied* request never reaches invoke, so
     it never produces a trace; denials surface via ``explain_denial``).

It then prints the versioned export envelope, attaching optional human
correction metadata to one trace. Everything is offline and deterministic.

Run with: ``python examples/trace_export_demo.py``
"""

from __future__ import annotations

import asyncio
import json

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    DriverError,
    HMACTokenProvider,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    export_action_traces,
    make_billing_driver,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.models import CapabilityRequest, ImplementationRef

_SECRET = "example-secret-do-not-use-in-prod"


def _build_kernel() -> Kernel:
    capabilities = [
        Capability(
            capability_id="billing.list_invoices",
            name="List Invoices",
            description="List invoices for a customer",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            allowed_fields=["id", "amount", "currency", "status", "date"],
            impl=ImplementationRef(driver_id="billing", operation="list_invoices"),
        ),
        Capability(
            capability_id="billing.flaky_report",
            name="Flaky Report",
            description="A report whose backing service is currently failing",
            safety_class=SafetyClass.READ,
            impl=ImplementationRef(driver_id="billing", operation="flaky_report"),
        ),
    ]
    registry = CapabilityRegistry()
    registry.register_many(capabilities)

    driver = make_billing_driver()

    def flaky_report(ctx: ExecutionContext) -> object:
        raise DriverError("reporting backend is unavailable")

    driver.register_handler("flaky_report", flaky_report)

    router = StaticRouter(
        routes={
            "billing.list_invoices": ["billing"],
            "billing.flaky_report": ["billing"],
        }
    )
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=router,
    )
    kernel.register_driver(driver)
    return kernel


async def main() -> None:
    kernel = _build_kernel()
    principal = Principal(
        principal_id="agent-007",
        roles=["reader"],
        attributes={"tenant": "acme"},
    )

    # 1. A successful READ — produces a status="succeeded" trace.
    list_req = CapabilityRequest(capability_id="billing.list_invoices", goal="list invoices")
    list_token = kernel.get_token(list_req, principal, justification="")
    ok_frame = await kernel.invoke(
        list_token,
        principal=principal,
        args={"operation": "list_invoices", "status": "paid"},
    )
    print(f"succeeded: action_id={ok_frame.action_id} facts={len(ok_frame.facts)}")

    # 2. A failing READ — produces a status="failed" trace.
    flaky_req = CapabilityRequest(capability_id="billing.flaky_report", goal="run report")
    flaky_token = kernel.get_token(flaky_req, principal, justification="")
    failed_action_id = ""
    try:
        await kernel.invoke(flaky_token, principal=principal, args={"operation": "flaky_report"})
    except DriverError as exc:
        print(f"failed:    {exc}")
        # The failure was still recorded; grab the most recent trace's id.
        failed_action_id = kernel._traces.list_all()[-1].action_id

    # Export everything. Attach an optional human correction to the failed run.
    corrections = (
        {failed_action_id: {"corrected_by": "on-call", "note": "known outage; retried later"}}
        if failed_action_id
        else None
    )
    envelope = export_action_traces(kernel._traces.list_all(), corrections=corrections)

    print("\nExported trace envelope:")
    print(json.dumps(envelope, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
