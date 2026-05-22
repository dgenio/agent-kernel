"""tutorial.py — "Secure your first MCP tool in 5 minutes" (offline edition).

The full written walkthrough lives in ``docs/tutorial.md``. This script is the
runnable companion: it covers every step a new reader will see, using only
the in-process :class:`InMemoryDriver` so it has zero external dependencies
and runs in CI.

What this demo proves end-to-end:
  1. Registering a capability with a sensitivity tag and ``allowed_fields``.
  2. Issuing a signed token for a principal that satisfies policy.
  3. Invoking the capability and observing the Frame in three response modes
     (``summary`` / ``table`` / ``handle_only``) — PII never appears in any
     of them.
  4. Expanding a Handle to retrieve filtered raw data on demand.
  5. A policy denial: the same token model rejects a writer call from a
     reader principal, and the denial carries a stable ``reason_code``.
  6. Auditability: ``explain()`` returns the full :class:`ActionTrace`.

Run with: ``python examples/tutorial.py``
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_KERNEL_SECRET", "tutorial-secret-do-not-use-in-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
)
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.errors import HandleConstraintViolation, PolicyDenied
from agent_kernel.models import CapabilityRequest, ImplementationRef

# A tiny, deterministic dataset that mixes safe and PII-bearing fields.
# Email is present on purpose: the firewall must keep it out of the LLM-safe
# Frame unless the capability declared it under ``allowed_fields``.
INVOICES: list[dict[str, object]] = [
    {
        "id": "INV-001",
        "customer_name": "Alice",
        "email": "alice@example.com",
        "amount": 120.0,
        "status": "paid",
    },
    {
        "id": "INV-002",
        "customer_name": "Bob",
        "email": "bob@example.com",
        "amount": 540.0,
        "status": "unpaid",
    },
    {
        "id": "INV-003",
        "customer_name": "Carol",
        "email": "carol@example.com",
        "amount": 75.0,
        "status": "paid",
    },
]


def build_registry() -> CapabilityRegistry:
    """Register one READ capability (PII-tagged) and one WRITE capability."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="billing.invoices.list",
            name="List Invoices",
            description="List recent invoices",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            # The Firewall will drop every column that isn't on this list.
            allowed_fields=["id", "customer_name", "amount", "status"],
            tags=["billing", "invoices", "list"],
            impl=ImplementationRef(driver_id="memory", operation="list_invoices"),
        )
    )
    registry.register(
        Capability(
            capability_id="billing.invoices.create",
            name="Create Invoice",
            description="Create a new invoice",
            safety_class=SafetyClass.WRITE,
            tags=["billing", "invoices", "create"],
            impl=ImplementationRef(driver_id="memory", operation="create_invoice"),
        )
    )
    return registry


def build_driver() -> InMemoryDriver:
    """A driver that returns the synthetic invoices dataset on read."""
    driver = InMemoryDriver()

    def list_invoices(_ctx: ExecutionContext) -> list[dict[str, object]]:
        return list(INVOICES)

    def create_invoice(_ctx: ExecutionContext) -> dict[str, object]:
        return {"id": "INV-004", "status": "draft"}

    driver.register_handler("list_invoices", list_invoices)
    driver.register_handler("create_invoice", create_invoice)
    return driver


async def main() -> None:
    print("=== Step 1: Register capabilities ===")
    registry = build_registry()
    for cap in registry.list_all():
        print(f"  • {cap.capability_id} ({cap.safety_class.value})")

    print("\n=== Step 2: Wire the kernel ===")
    router = StaticRouter(
        routes={
            "billing.invoices.list": ["memory"],
            "billing.invoices.create": ["memory"],
        }
    )
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="tutorial-secret-do-not-use-in-prod"),
        router=router,
    )
    kernel.register_driver(build_driver())

    # PII-tagged capabilities require a ``tenant`` attribute on the principal.
    reader = Principal(principal_id="alice", roles=["reader"], attributes={"tenant": "acme"})

    print(f"  principal: {reader.principal_id}  roles={reader.roles}")

    print("\n=== Step 3: Grant a token ===")
    list_req = CapabilityRequest(
        capability_id="billing.invoices.list", goal="list recent invoices"
    )
    token = kernel.get_token(list_req, reader, justification="")
    print(f"  token_id:    {token.token_id}")
    print(f"  capability:  {token.capability_id}")
    print(f"  expires_at:  {token.expires_at.isoformat()}")

    print("\n=== Step 4: Invoke in summary mode ===")
    frame = await kernel.invoke(token, principal=reader, args={"operation": "list_invoices"})
    print(f"  mode:        {frame.response_mode}")
    print("  facts:")
    for fact in frame.facts:
        print(f"    • {fact}")
    if frame.handle:
        print(f"  handle:      {frame.handle.handle_id}")

    print("\n=== Step 5: Invoke in table mode (allowed_fields enforced) ===")
    table_token = kernel.get_token(list_req, reader, justification="")
    table_frame = await kernel.invoke(
        table_token,
        principal=reader,
        args={"operation": "list_invoices"},
        response_mode="table",
    )
    print(f"  mode:        {table_frame.response_mode}")
    print(f"  rows shown:  {len(table_frame.table_preview)}")
    print("  preview:")
    for row in table_frame.table_preview[:2]:
        print(f"    {row}")
    leaked = [row for row in table_frame.table_preview if "email" in row]
    assert leaked == [], (
        f"firewall regression: 'email' is not in allowed_fields but reached "
        f"the table-mode Frame in {len(leaked)} row(s): {leaked}"
    )
    print(f"  PII fields leaked into Frame: {len(leaked)}  (asserted == 0)")

    print("\n=== Step 6: Invoke in handle_only mode and expand ===")
    handle_token = kernel.get_token(list_req, reader, justification="")
    handle_frame = await kernel.invoke(
        handle_token,
        principal=reader,
        args={"operation": "list_invoices"},
        response_mode="handle_only",
    )
    assert handle_frame.handle is not None, "handle_only mode must return a Handle"
    expanded = kernel.expand(
        handle_frame.handle,
        query={"offset": 0, "limit": 2, "fields": ["id", "amount"]},
        principal=reader,
    )
    print(f"  expanded rows: {len(expanded.table_preview)}")
    for row in expanded.table_preview:
        print(f"    {row}")
    # Prove the new grant-constraint enforcement (#76): requesting a field the
    # grant doesn't allow must raise HandleConstraintViolation. Without this
    # check a future regression on the expand path would silently leak data
    # that the firewall already excluded from the summary/table previews.
    try:
        kernel.expand(
            handle_frame.handle,
            query={"fields": ["email"]},
            principal=reader,
        )
    except HandleConstraintViolation as exc:
        print(f"  blocked disallowed field: reason_code={exc.reason_code}")
    else:  # pragma: no cover - defensive
        raise SystemExit("Expected HandleConstraintViolation for disallowed field on expand")

    print("\n=== Step 7: Watch policy enforcement deny a writer call ===")
    create_req = CapabilityRequest(
        capability_id="billing.invoices.create", goal="create an invoice"
    )
    try:
        kernel.get_token(create_req, reader, justification="reader trying a write — should fail")
    except PolicyDenied as exc:
        print(f"  denied:      {exc}")
        print(f"  reason_code: {exc.reason_code}")
    else:  # pragma: no cover - defensive
        raise SystemExit("Expected PolicyDenied for reader on a WRITE capability")

    print("\n=== Step 8: Audit the read with explain() ===")
    trace = kernel.explain(frame.action_id)
    print(f"  action_id:   {trace.action_id}")
    print(f"  capability:  {trace.capability_id}")
    print(f"  principal:   {trace.principal_id}")
    print(f"  driver:      {trace.driver_id}")
    print(f"  invoked_at:  {trace.invoked_at.isoformat()}")

    print("\n✓ tutorial.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
