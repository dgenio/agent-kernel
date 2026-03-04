"""Shared test fixtures for agent-kernel tests."""

from __future__ import annotations

import pytest

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
    make_billing_driver,
)
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.models import ImplementationRef

# ── Capabilities ───────────────────────────────────────────────────────────────


@pytest.fixture()
def capabilities() -> list[Capability]:
    return [
        Capability(
            capability_id="billing.list_invoices",
            name="List Invoices",
            description="List all invoices for a customer",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            allowed_fields=["id", "amount", "currency", "status", "date"],
            tags=["billing", "invoices", "list"],
            impl=ImplementationRef(driver_id="billing", operation="list_invoices"),
        ),
        Capability(
            capability_id="billing.get_invoice",
            name="Get Invoice",
            description="Get a single invoice by ID",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.PII,
            allowed_fields=["id", "amount", "currency", "status", "date", "line_items"],
            tags=["billing", "invoice", "get", "detail"],
            impl=ImplementationRef(driver_id="billing", operation="get_invoice"),
        ),
        Capability(
            capability_id="billing.summarize_spend",
            name="Summarize Spend",
            description="Summarize total spend by currency and status",
            safety_class=SafetyClass.READ,
            tags=["billing", "summary", "spend", "analytics"],
            impl=ImplementationRef(driver_id="billing", operation="summarize_spend"),
        ),
        Capability(
            capability_id="billing.update_invoice",
            name="Update Invoice",
            description="Update an existing invoice",
            safety_class=SafetyClass.WRITE,
            tags=["billing", "invoice", "update", "write"],
            impl=ImplementationRef(driver_id="billing", operation="update_invoice"),
        ),
        Capability(
            capability_id="billing.delete_invoice",
            name="Delete Invoice",
            description="Permanently delete an invoice",
            safety_class=SafetyClass.DESTRUCTIVE,
            tags=["billing", "invoice", "delete", "destructive"],
            impl=ImplementationRef(driver_id="billing", operation="delete_invoice"),
        ),
    ]


@pytest.fixture()
def registry(capabilities: list[Capability]) -> CapabilityRegistry:
    reg = CapabilityRegistry()
    reg.register_many(capabilities)
    return reg


# ── Principals ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def reader_principal() -> Principal:
    return Principal(
        principal_id="user-reader-001",
        roles=["reader"],
        attributes={"tenant": "acme"},
    )


@pytest.fixture()
def writer_principal() -> Principal:
    return Principal(
        principal_id="user-writer-001",
        roles=["reader", "writer"],
        attributes={"tenant": "acme"},
    )


@pytest.fixture()
def admin_principal() -> Principal:
    return Principal(
        principal_id="user-admin-001",
        roles=["reader", "writer", "admin"],
        attributes={"tenant": "acme"},
    )


@pytest.fixture()
def service_principal() -> Principal:
    return Principal(
        principal_id="svc-analytics-001",
        roles=["reader", "service"],
        attributes={"tenant": "acme"},
    )


# ── Drivers ────────────────────────────────────────────────────────────────────


@pytest.fixture()
def billing_driver() -> InMemoryDriver:
    return make_billing_driver()


@pytest.fixture()
def memory_driver() -> InMemoryDriver:
    driver = InMemoryDriver(driver_id="memory")

    def echo(ctx: ExecutionContext) -> dict[str, object]:
        return {"echo": ctx.args, "capability_id": ctx.capability_id}

    driver.register_handler("billing.list_invoices", echo)
    driver.register_handler("billing.get_invoice", echo)
    driver.register_handler("billing.summarize_spend", echo)
    driver.register_handler("billing.update_invoice", echo)
    driver.register_handler("billing.delete_invoice", echo)
    return driver


# ── Token provider ─────────────────────────────────────────────────────────────


@pytest.fixture()
def token_provider() -> HMACTokenProvider:
    return HMACTokenProvider(secret="test-secret-do-not-use-in-prod")


# ── Kernel ─────────────────────────────────────────────────────────────────────


@pytest.fixture()
def kernel(registry: CapabilityRegistry, memory_driver: InMemoryDriver) -> Kernel:
    router = StaticRouter(
        routes={
            "billing.list_invoices": ["memory"],
            "billing.get_invoice": ["memory"],
            "billing.summarize_spend": ["memory"],
            "billing.update_invoice": ["memory"],
            "billing.delete_invoice": ["memory"],
        }
    )
    k = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
    )
    k.register_driver(memory_driver)
    return k
