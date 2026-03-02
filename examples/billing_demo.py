"""billing_demo.py — InMemoryDriver with billing dataset, budgets, handles, pagination.

Run with: python examples/billing_demo.py
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_KERNEL_SECRET", "example-secret-do-not-use-in-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    Firewall,
    HMACTokenProvider,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    make_billing_driver,
)
from agent_kernel.firewall.budgets import Budgets
from agent_kernel.models import CapabilityRequest, ImplementationRef


def build_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="billing.list_invoices",
            name="List Invoices",
            description="List all invoices, optionally filtered by status",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            allowed_fields=["id", "customer_name", "amount", "currency", "status", "date"],
            tags=["billing", "invoices", "list"],
            impl=ImplementationRef(driver_id="billing", operation="list_invoices"),
        )
    )
    registry.register(
        Capability(
            capability_id="billing.summarize_spend",
            name="Summarize Spend",
            description="Summarize total spend per currency and status",
            safety_class=SafetyClass.READ,
            tags=["billing", "summary", "analytics"],
            impl=ImplementationRef(driver_id="billing", operation="summarize_spend"),
        )
    )
    return registry


async def main() -> None:
    registry = build_registry()
    billing_driver = make_billing_driver()

    router = StaticRouter(
        routes={
            "billing.list_invoices": ["billing"],
            "billing.summarize_spend": ["billing"],
        }
    )

    # Tight budgets to show enforcement
    firewall = Firewall(budgets=Budgets(max_rows=5, max_fields=10, max_chars=2000))

    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="example-secret-do-not-use-in-prod"),
        router=router,
        firewall=firewall,
    )
    kernel.register_driver(billing_driver)

    # Reader with tenant attribute (required for PII capabilities)
    analyst = Principal(
        principal_id="analyst-001",
        roles=["reader"],
        attributes={"tenant": "acme"},
    )

    print("=== Billing Demo ===\n")

    # ── List invoices (summary mode) ─────────────────────────────────────────
    print("--- list_invoices (summary) ---")
    token = kernel.get_token(
        CapabilityRequest(capability_id="billing.list_invoices", goal="list invoices"),
        analyst,
        justification="",
    )
    frame = await kernel.invoke(
        token,
        principal=analyst,
        args={"operation": "list_invoices"},
        response_mode="summary",
    )
    print(f"Facts ({len(frame.facts)}):")
    for f in frame.facts:
        print(f"  • {f}")
    if frame.warnings:
        print("Warnings:")
        for w in frame.warnings[:3]:
            print(f"  ⚠ {w}")

    # ── Expand: pagination ───────────────────────────────────────────────────
    print("\n--- expand: first 3 rows, id+amount+status ---")
    if frame.handle:
        expanded = kernel.expand(
            frame.handle,
            query={"offset": 0, "limit": 3, "fields": ["id", "amount", "status"]},
        )
        for row in expanded.table_preview:
            print(f"  {row}")

    # ── Expand: filter ───────────────────────────────────────────────────────
    print("\n--- expand: filter overdue ---")
    if frame.handle:
        overdue = kernel.expand(
            frame.handle,
            query={"filter": {"status": "overdue"}, "limit": 3, "fields": ["id", "amount"]},
        )
        print(f"  Overdue rows returned: {len(overdue.table_preview)}")
        for row in overdue.table_preview:
            print(f"  {row}")

    # ── Summarize spend ──────────────────────────────────────────────────────
    print("\n--- summarize_spend ---")
    token2 = kernel.get_token(
        CapabilityRequest(capability_id="billing.summarize_spend", goal="summarize"),
        analyst,
        justification="",
    )
    frame2 = await kernel.invoke(
        token2,
        principal=analyst,
        args={"operation": "summarize_spend"},
        response_mode="summary",
    )
    for f in frame2.facts:
        print(f"  • {f}")

    # ── Explain ──────────────────────────────────────────────────────────────
    print("\n--- explain ---")
    trace = kernel.explain(frame2.action_id)
    print(f"  Action:    {trace.action_id}")
    print(f"  Capability:{trace.capability_id}")
    print(f"  Driver:    {trace.driver_id}")
    print(f"  At:        {trace.invoked_at.isoformat()}")

    print("\n✓ billing_demo.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
