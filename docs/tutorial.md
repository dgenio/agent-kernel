# Secure your first MCP tool in 5 minutes

This walkthrough takes a brand-new reader from `pip install` to a working,
authorized, audited tool invocation in roughly five minutes. Every code block
is copy-pasteable; the runnable companion is
[`examples/tutorial.py`](../examples/tutorial.py) (covered by CI).

> The PyPI package is **`weaver-kernel`** but the Python import is
> **`agent_kernel`**. We use both names in this document.

## What you'll learn

By the end of this page you will have seen, in this order:

1. How to register a **capability** and how its `safety_class`,
   `sensitivity`, and `allowed_fields` shape authorization.
2. How a **principal** is created and why some attributes (like `tenant`)
   are required for PII-tagged capabilities.
3. How to issue a signed **token** with `kernel.get_token(...)`.
4. How `kernel.invoke(...)` returns a bounded **Frame** in `summary`,
   `table`, or `handle_only` modes — and why `email` never appears in any
   of them.
5. How to retrieve filtered raw rows by expanding a **Handle**.
6. What a **policy denial** looks like and how to branch on its stable
   `reason_code`.
7. How `kernel.explain(action_id)` returns an audit **ActionTrace**.
8. How to swap the in-process driver for a real **MCP** server.

## 0. Install

```bash
pip install weaver-kernel
```

For the MCP section near the end, also install the optional extra:

```bash
pip install "weaver-kernel[mcp]"
```

Set a stable HMAC secret for the process. In production this should come
from a real secret store; the example uses a fixed value so the output is
reproducible:

```python
import os
os.environ["AGENT_KERNEL_SECRET"] = "tutorial-secret-do-not-use-in-prod"
```

## 1. Register a capability

A capability is the unit of authorization. The `safety_class` controls
which roles may call it. The `sensitivity` tag tells the policy and
firewall how to treat the data. `allowed_fields` is the projection the
firewall applies before any row reaches the LLM.

```python
from agent_kernel import (
    Capability,
    CapabilityRegistry,
    ImplementationRef,
    SafetyClass,
    SensitivityTag,
)

registry = CapabilityRegistry()
registry.register(
    Capability(
        capability_id="billing.invoices.list",
        name="List Invoices",
        description="List recent invoices",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.PII,
        allowed_fields=["id", "customer_name", "amount", "status"],
        tags=["billing", "invoices", "list"],
        impl=ImplementationRef(driver_id="memory", operation="list_invoices"),
    )
)
```

> `email`, `phone`, and other non-listed columns will never reach the LLM
> even if the driver returns them.

## 2. Wire a driver and the kernel

`InMemoryDriver` keeps the tutorial offline. The same pattern works with
`HTTPDriver` or `MCPDriver` — see step 8.

```python
from agent_kernel import HMACTokenProvider, InMemoryDriver, Kernel, StaticRouter
from agent_kernel.drivers.base import ExecutionContext

INVOICES = [
    {"id": "INV-001", "customer_name": "Alice", "email": "alice@example.com", "amount": 120.0, "status": "paid"},
    {"id": "INV-002", "customer_name": "Bob",   "email": "bob@example.com",   "amount": 540.0, "status": "unpaid"},
    {"id": "INV-003", "customer_name": "Carol", "email": "carol@example.com", "amount":  75.0, "status": "paid"},
]

driver = InMemoryDriver()
driver.register_handler("list_invoices", lambda ctx: list(INVOICES))

kernel = Kernel(
    registry=registry,
    token_provider=HMACTokenProvider(secret="tutorial-secret-do-not-use-in-prod"),
    router=StaticRouter(routes={"billing.invoices.list": ["memory"]}),
)
kernel.register_driver(driver)
```

## 3. Create a principal

The `DefaultPolicyEngine` requires a `tenant` attribute on the principal
for any PII-tagged capability. Without it, the grant is denied with
`reason_code="missing_tenant_attribute"`.

```python
from agent_kernel import Principal

alice = Principal(principal_id="alice", roles=["reader"], attributes={"tenant": "acme"})
```

## 4. Grant a token

`get_token` runs the policy engine and returns a signed
`CapabilityToken`. No token, no invocation.

```python
from agent_kernel.models import CapabilityRequest

request = CapabilityRequest(capability_id="billing.invoices.list", goal="list recent invoices")
token = kernel.get_token(request, alice, justification="")
print(token.token_id, token.expires_at)
```

## 5. Invoke and observe the Frame

The default `response_mode` is `"summary"`. The Frame holds compact
facts about the data plus a Handle the LLM can expand later.

```python
import asyncio

frame = asyncio.run(kernel.invoke(token, principal=alice, args={"operation": "list_invoices"}))
for fact in frame.facts:
    print("•", fact)
print("handle:", frame.handle and frame.handle.handle_id)
```

Try `response_mode="table"` to get a row preview that respects
`allowed_fields`. Try `response_mode="handle_only"` to skip the preview
entirely — the LLM gets only a reference. In every mode, **`email` is
absent** from the Frame, because it is not in `allowed_fields`.

```python
table_frame = asyncio.run(
    kernel.invoke(
        kernel.get_token(request, alice, justification=""),
        principal=alice,
        args={"operation": "list_invoices"},
        response_mode="table",
    )
)
assert all("email" not in row for row in table_frame.table_preview)
```

## 6. Expand a Handle

Handles let the LLM stay inside its context budget while still pulling
specific rows or fields on demand. The expand query supports `offset`,
`limit`, `fields`, and an equality `filter`.

```python
handle_frame = asyncio.run(
    kernel.invoke(
        kernel.get_token(request, alice, justification=""),
        principal=alice,
        args={"operation": "list_invoices"},
        response_mode="handle_only",
    )
)
expanded = kernel.expand(
    handle_frame.handle,
    query={"offset": 0, "limit": 2, "fields": ["id", "amount"]},
)
print(expanded.table_preview)
# [{'id': 'INV-001', 'amount': 120.0}, {'id': 'INV-002', 'amount': 540.0}]
```

> **Where the security boundary is today.** The `Firewall` enforces
> `allowed_fields` when it builds the `summary` and `table` previews, so
> disallowed columns never reach the LLM-safe Frame. `HandleStore.expand()`
> currently filters by whatever `fields` the caller passes in the query
> against the stored raw rows — it does **not yet** re-apply the
> capability's `allowed_fields` projection. Until the in-flight grant
> constraint work lands (tracking issue
> [#76](https://github.com/dgenio/agent-kernel/issues/76), PR
> [#79](https://github.com/dgenio/agent-kernel/pull/79)), treat handle
> expansion as authorized-but-field-unconstrained: only request `fields`
> the caller is allowed to see.

## 7. Watch policy enforcement

Add a WRITE capability and try to call it as the reader principal. The
denial carries both a human-readable `reason` and a stable
`reason_code` your code can branch on.

```python
from agent_kernel.errors import PolicyDenied

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

try:
    kernel.get_token(
        CapabilityRequest(capability_id="billing.invoices.create", goal="create an invoice"),
        alice,
        justification="reader trying a write — should fail",
    )
except PolicyDenied as exc:
    print(exc.reason_code)   # 'missing_role'
    print(str(exc))          # "WRITE capabilities require the 'writer' or 'admin' role..."
```

Stable reason codes come from `agent_kernel.policy_reasons.DenialReason`.
Tests should assert on the code, not on the human-readable string.

## 8. Audit with `explain()`

Every successful invocation creates an `ActionTrace` keyed by
`frame.action_id`. The trace records who, what, when, and which driver
served the request — the auditable half of weaver-spec invariant I-02.

```python
trace = kernel.explain(frame.action_id)
print(trace.action_id, trace.capability_id, trace.principal_id, trace.driver_id)
```

## 9. Swap the driver for an MCP server

The kernel doesn't care whether the driver lives in-process, behind
HTTP, or behind an MCP server — capabilities, policy, tokens, and
firewall behave identically. To talk to a real MCP server, replace
`InMemoryDriver` with `MCPDriver` (full transport details, including
Streamable HTTP, live in [`docs/integrations.md`](integrations.md)):

```python
from agent_kernel.drivers.mcp import MCPDriver

driver = MCPDriver.from_stdio(
    command="python",
    args=["-m", "my_mcp_server"],
    server_name="local-tools",
)
kernel.register_driver(driver)

# Discover the MCP server's tools and register each as an agent-kernel
# capability under a namespace. Set safety_class/sensitivity/allowed_fields
# on the resulting Capability objects to apply policy and the firewall.
capabilities = asyncio.run(driver.discover(namespace="billing"))
registry.register_many(capabilities)
```

That's the whole tutorial. From here:

- [`docs/security.md`](security.md) — threat model, what HMAC tokens do
  and do not protect against.
- [`docs/context_firewall.md`](context_firewall.md) — redaction,
  summarization, and budget details.
- [`docs/capabilities.md`](capabilities.md) — designing capabilities
  for large tool ecosystems.
- [`docs/integrations.md`](integrations.md) — full MCP and HTTP driver
  integration patterns.
