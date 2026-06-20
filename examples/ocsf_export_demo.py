"""ocsf_export_demo.py — export the audit trail as OCSF/AOS SIEM events (#176).

Security teams consume agent activity through SIEMs, and OCSF is the schema
those pipelines speak. This script records the three audited event kinds — an
invocation, a policy **denial**, and a handle **expansion** — then maps the
whole audit trail to OCSF API Activity (class 6003) events enriched per the
OWASP Agent Observability Standard, ready to ship to a SIEM.

It also prints the in-process :class:`KernelStats` snapshot (#179), the cheap
counters that answer "how many grants/denials/expansions happened?" without
exporting anything.

Everything is offline and deterministic. Run with:
``python examples/ocsf_export_demo.py``
"""

from __future__ import annotations

import asyncio
import json

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    Kernel,
    PolicyDenied,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    traces_to_ocsf,
)
from weaver_kernel.drivers.memory import InMemoryDriver
from weaver_kernel.models import CapabilityRequest, ImplementationRef

_SECRET = "example-secret-do-not-use-in-prod"


def _build_kernel() -> Kernel:
    registry = CapabilityRegistry()
    registry.register_many(
        [
            Capability(
                capability_id="billing.list_invoices",
                name="List Invoices",
                description="List invoices for a customer",
                safety_class=SafetyClass.READ,
                sensitivity=SensitivityTag.PII,
                impl=ImplementationRef(driver_id="billing", operation="list_invoices"),
            ),
            Capability(
                capability_id="billing.delete_invoice",
                name="Delete Invoice",
                description="Permanently delete an invoice",
                safety_class=SafetyClass.DESTRUCTIVE,
                impl=ImplementationRef(driver_id="billing", operation="delete_invoice"),
            ),
        ]
    )
    driver = InMemoryDriver(driver_id="billing")
    driver.register_handler(
        "list_invoices",
        lambda _ctx: [{"id": i, "amount": i * 10.0, "status": "paid"} for i in range(5)],
    )
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=StaticRouter(
            routes={"billing.list_invoices": ["billing"], "billing.delete_invoice": ["billing"]}
        ),
    )
    kernel.register_driver(driver)
    return kernel


async def main() -> None:
    kernel = _build_kernel()
    reader = Principal(principal_id="agent-007", roles=["reader"], attributes={"tenant": "acme"})

    # 1. A successful invocation (event_type="invoke").
    req = CapabilityRequest(capability_id="billing.list_invoices", goal="list invoices")
    token = kernel.get_token(req, reader, justification="monthly review")
    frame = await kernel.invoke(token, principal=reader, args={"operation": "list_invoices"})

    # 2. A handle expansion (event_type="expand").
    assert frame.handle is not None
    kernel.expand(frame.handle, query={"limit": 2}, principal=reader)

    # 3. A policy denial (event_type="deny") — a reader cannot delete.
    deny_req = CapabilityRequest(capability_id="billing.delete_invoice", goal="delete invoice")
    try:
        kernel.grant_capability(deny_req, reader, justification="cleanup")
    except PolicyDenied as exc:
        print(f"denied as expected: reason_code={exc.reason_code}")

    # Map the whole audit trail to OCSF/AOS events for a SIEM.
    events = traces_to_ocsf(kernel.list_traces())
    print(f"\n{len(events)} OCSF API Activity events:")
    print(json.dumps(events, indent=2))

    # In-process counters (no export required).
    stats = kernel.stats
    print("\nKernelStats snapshot:")
    print(
        json.dumps(
            {
                "grants": stats.grants,
                "denials": stats.denials,
                "invocations": stats.invocations,
                "expansions": stats.expansions,
                "handle_stores": stats.handle_stores,
                "denials_by_reason": dict(stats.denials_by_reason),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
