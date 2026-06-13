"""Durable, verifiable audit trail + durable revocation (issues #126, #127).

Runs fully offline. Demonstrates:

1. Recording invocations to a SQLite-backed, hash-chained trace store.
2. Verifying chain integrity — and detecting tampering.
3. Revocation that survives a fresh token-provider instance (as it would across
   a process restart) via a SQLite revocation store.

Run: ``python examples/persistent_audit_demo.py``
"""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
from pathlib import Path

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    CapabilityRequest,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from weaver_kernel.errors import TokenRevoked
from weaver_kernel.stores import SQLiteRevocationStore, SQLiteTraceStore

SECRET = "persistent-audit-demo-secret"  # demo only — set WEAVER_KERNEL_SECRET in production


def _build_kernel(trace_db: Path, provider: HMACTokenProvider) -> Kernel:
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="billing.list_invoices",
            name="List Invoices",
            description="List invoices for a customer",
            safety_class=SafetyClass.READ,
        )
    )
    driver = InMemoryDriver(driver_id="billing")
    driver.register_handler("billing.list_invoices", lambda ctx: [{"id": 1, "amount": 42}])
    kernel = Kernel(
        registry=registry,
        token_provider=provider,
        router=StaticRouter(routes={"billing.list_invoices": ["billing"]}),
        trace_store=SQLiteTraceStore(trace_db, secret=SECRET),
    )
    kernel.register_driver(driver)
    return kernel


async def _main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="weaver-audit-demo-"))
    trace_db = workdir / "audit.db"
    revoke_db = workdir / "revoked.db"

    provider = HMACTokenProvider(secret=SECRET, revocation_store=SQLiteRevocationStore(revoke_db))
    kernel = _build_kernel(trace_db, provider)
    principal = Principal(principal_id="u1", roles=["reader"])
    request = CapabilityRequest(capability_id="billing.list_invoices", goal="list invoices")

    # 1. Record a couple of invocations into the durable, hash-chained store.
    for _ in range(2):
        token = kernel.get_token(request, principal, justification="month-end review")
        await kernel.invoke(
            token, principal=principal, args={"operation": "billing.list_invoices"}
        )

    store = SQLiteTraceStore(trace_db, secret=SECRET)
    print(f"recorded {len(store.list_all())} traces")
    print(f"verify (intact): {store.verify_chain().detail}")

    # 2. Tamper directly with the database, then re-verify.
    conn = sqlite3.connect(str(trace_db))
    conn.execute('UPDATE traces SET payload = \'{"action_id":"x"}\' WHERE seq = 0')
    conn.commit()
    conn.close()
    tampered = SQLiteTraceStore(trace_db, secret=SECRET).verify_chain()
    print(f"verify (tampered): ok={tampered.ok}, first_bad_seq={tampered.first_bad_seq}")

    # 3. Durable revocation: revoke a token, then prove a *fresh* provider
    #    (as after a restart) still honours the revocation from disk.
    token = kernel.get_token(request, principal, justification="will be revoked")
    provider.revoke(token.token_id)
    fresh = HMACTokenProvider(secret=SECRET, revocation_store=SQLiteRevocationStore(revoke_db))
    try:
        fresh.verify(
            token, expected_principal_id="u1", expected_capability_id="billing.list_invoices"
        )
        print("ERROR: revoked token verified")
    except TokenRevoked:
        print("revoked token rejected by a fresh provider (survives restart)")


if __name__ == "__main__":
    asyncio.run(_main())
