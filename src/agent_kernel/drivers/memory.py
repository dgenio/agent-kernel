"""In-memory driver for testing and local demos."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from ..errors import DriverError
from ..models import RawResult
from .base import ExecutionContext

Handler = Callable[[ExecutionContext], Any]


class InMemoryDriver:
    """A driver that executes capabilities using registered Python callables.

    This driver is primarily intended for unit tests, demos, and
    local development where no external API is available.
    """

    def __init__(self, driver_id: str = "memory") -> None:
        self._driver_id = driver_id
        self._handlers: dict[str, Handler] = {}

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver."""
        return self._driver_id

    def register_handler(self, operation: str, handler: Handler) -> None:
        """Register a Python callable as the handler for an operation.

        Args:
            operation: The operation name (must match ``ImplementationRef.operation``).
            handler: A callable ``(ExecutionContext) -> Any`` that performs the operation.
        """
        self._handlers[operation] = handler

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Execute a capability via its registered handler.

        The operation is looked up from ``ctx.args.get("operation")`` first,
        then falls back to ``ctx.capability_id``.

        Args:
            ctx: The execution context.

        Returns:
            :class:`RawResult` wrapping the handler's return value.

        Raises:
            DriverError: If no handler is registered or the handler raises.
        """
        operation = str(ctx.args.get("operation", ctx.capability_id))
        handler = self._handlers.get(operation)
        if handler is None:
            raise DriverError(
                f"InMemoryDriver '{self._driver_id}' has no handler for "
                f"operation='{operation}'. Register one with register_handler()."
            )
        try:
            data = handler(ctx)
        except Exception as exc:
            raise DriverError(f"Handler for operation='{operation}' raised: {exc}") from exc
        return RawResult(capability_id=ctx.capability_id, data=data)


# ── Billing dataset factory ───────────────────────────────────────────────────


def _make_billing_dataset(n: int = 200) -> list[dict[str, Any]]:
    """Generate a deterministic synthetic billing dataset.

    Uses :class:`random.Random` seeded with ``42`` so the output is always
    the same regardless of global random state.

    Args:
        n: Number of invoice records to generate.

    Returns:
        A list of invoice dicts.
    """
    rng = random.Random(42)
    statuses = ["paid", "unpaid", "overdue"]
    currencies = ["USD", "EUR", "GBP"]
    first_names = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hiro"]
    last_names = ["Smith", "Jones", "Lee", "Brown", "Taylor", "Wilson", "Davis"]

    records: list[dict[str, Any]] = []
    for i in range(1, n + 1):
        fname = rng.choice(first_names)
        lname = rng.choice(last_names)
        name = f"{fname} {lname}"
        email = f"{fname.lower()}.{lname.lower()}{i}@example.com"
        phone = f"+1-555-{rng.randint(1000, 9999)}"
        amount = round(rng.uniform(10.0, 5000.0), 2)
        currency = rng.choice(currencies)
        status = rng.choice(statuses)
        year = rng.randint(2023, 2024)
        month = rng.randint(1, 12)
        day = rng.randint(1, 28)
        date_str = f"{year}-{month:02d}-{day:02d}"
        line_items = [
            {
                "description": f"Item {j}",
                "qty": rng.randint(1, 5),
                "unit_price": round(rng.uniform(5.0, 500.0), 2),
            }
            for j in range(1, rng.randint(1, 4) + 1)
        ]
        records.append(
            {
                "id": f"INV-{i:04d}",
                "customer_name": name,
                "email": email,
                "phone": phone,
                "amount": amount,
                "currency": currency,
                "status": status,
                "date": date_str,
                "line_items": line_items,
            }
        )
    return records


BILLING_DATASET: list[dict[str, Any]] = _make_billing_dataset()


def make_billing_driver() -> InMemoryDriver:
    """Return an :class:`InMemoryDriver` pre-loaded with billing operations.

    Operations:
        - ``list_invoices`` — returns all invoices (filtered by ``status`` if provided).
        - ``get_invoice`` — returns a single invoice by ``id``.
        - ``summarize_spend`` — returns total spend per currency/status.

    Returns:
        A fully configured :class:`InMemoryDriver`.
    """
    driver = InMemoryDriver(driver_id="billing")

    def list_invoices(ctx: ExecutionContext) -> list[dict[str, Any]]:
        status_filter = ctx.args.get("status")
        data = BILLING_DATASET
        if status_filter:
            data = [r for r in data if r["status"] == status_filter]
        return data

    def get_invoice(ctx: ExecutionContext) -> dict[str, Any] | None:
        invoice_id = ctx.args.get("id")
        for record in BILLING_DATASET:
            if record["id"] == invoice_id:
                return record
        return None

    def summarize_spend(ctx: ExecutionContext) -> dict[str, Any]:
        totals: dict[str, dict[str, float]] = {}
        for record in BILLING_DATASET:
            cur = record["currency"]
            sta = record["status"]
            totals.setdefault(cur, {}).setdefault(sta, 0.0)
            totals[cur][sta] = round(totals[cur][sta] + record["amount"], 2)
        return {"totals": totals, "invoice_count": len(BILLING_DATASET)}

    driver.register_handler("list_invoices", list_invoices)
    driver.register_handler("get_invoice", get_invoice)
    driver.register_handler("summarize_spend", summarize_spend)
    return driver
