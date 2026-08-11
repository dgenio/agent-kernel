# Weaver Kernel

[![CI](https://github.com/dgenio/agent-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/dgenio/agent-kernel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dgenio/agent-kernel/actions/workflows/codeql.yml/badge.svg)](https://github.com/dgenio/agent-kernel/actions/workflows/codeql.yml)
[![Coverage ≥90%](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen.svg)](https://github.com/dgenio/agent-kernel/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Execution enforcement and audit for AI-agent actions.**

Weaver Kernel is an embeddable Python runtime that turns an authorization decision into a scoped, expiring capability grant, checks that grant before a configured driver executes, bounds the result returned through the Kernel path, and records an `ActionTrace` explaining what happened.

> **Authorize elsewhere if you want. Enforce here. Prove what ran.**

The built-in policy engine works standalone. The longer-term design deliberately keeps execution enforcement separable from whichever identity or policy system an adopter prefers.

## See it in under a minute

No model API key or network service is required:

```bash
python -m pip install weaver-kernel
python -m weaver_kernel.coding_agent_demo
```

The hermetic coding-agent scenario demonstrates a useful agent that can read a repository, edit bounded paths and run tests while secret access, out-of-scope writes and unapproved publication remain denied. It also prints the corresponding `kernel.explain()` / `ActionTrace` evidence.

[Read the coding-agent scenario and its boundaries.](docs/coding-agent-security.md)

## The boundary

```text
identity / workload authentication
          ↓
policy decision
(native Kernel policy today; external policy providers are an interoperability goal)
          ↓
┌────────────────────────────────────────────┐
│               Weaver Kernel                │
│                                            │
│ scoped grant → verify → execute            │
│                ↓                           │
│        bounded result + ActionTrace        │
└──────────────────────┬─────────────────────┘
                       ↓
                 MCP / HTTP / tool
```

For an action submitted through Kernel:

1. a `Principal` identifies the authorization subject supplied by the host;
2. policy evaluates the requested capability;
3. an allowed request receives a signed, expiring `CapabilityToken`;
4. `invoke()` verifies the token and principal before driver execution;
5. the Context Firewall transforms raw driver output before the default LLM-safe return path;
6. the invocation is recorded as an auditable `ActionTrace`.

## What Kernel does **not** claim

This is a security component, so the non-claims are part of the API contract:

- **Not complete mediation by itself.** Kernel is an in-process library. Code or framework surfaces that can invoke a tool around Kernel remain outside its protection.
- **Not authentication.** A `Principal` is authorization input. The host must derive it from an authentication mechanism it trusts.
- **Not a sandbox or prompt-injection cure.** Kernel can reject an unauthorized mediated action even when a model makes a bad decision; it does not make the model trustworthy.
- **Not yet transaction-level cryptographic authorization.** Current grants bind principal + capability + signed constraints + expiry. Exact binding to every normalized argument/resource/run/approval is an active design question (#258).
- **Not yet a distributed authorization service.** Some revocation, rate-limit, handle, budget and trace state is process-local; see #226 and the [security contract](docs/security-contract.md).

Read the concise **[Security Contract](docs/security-contract.md)** before relying on Kernel as a control boundary.

## Why not just framework guardrails?

Framework-native approvals and guardrails are useful and should be used where they solve the problem. Kernel is intended for teams that need an enforcement contract that is independent of one model framework and that couples the execution decision with scoped authority, bounded output and an inspectable receipt.

Every framework integration should publish a surface-by-surface coverage matrix. “Integrated with framework X” must never be interpreted as “every execution path in framework X is mediated.”

## Quickstart: the full Kernel API

The low-level API is explicit by design. A drop-in wrapper/middleware path is tracked in #104; the full API remains useful when you want direct control over capabilities, principals, drivers and traces.

```bash
pip install weaver-kernel
```

```python
import asyncio
import os

os.environ["WEAVER_KERNEL_SECRET"] = "replace-me-for-real-deployments"

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from weaver_kernel.models import CapabilityRequest

registry = CapabilityRegistry()
registry.register(
    Capability(
        capability_id="tasks.list",
        name="List Tasks",
        description="List tasks",
        safety_class=SafetyClass.READ,
        tags=["tasks"],
    )
)

driver = InMemoryDriver()
driver.register_handler(
    "tasks.list",
    lambda ctx: [{"id": 1, "title": "Buy milk"}],
)

kernel = Kernel(
    registry=registry,
    router=StaticRouter(routes={"tasks.list": ["memory"]}),
)
kernel.register_driver(driver)


async def main() -> None:
    principal = Principal(principal_id="alice", roles=["reader"])
    token = kernel.get_token(
        CapabilityRequest(capability_id="tasks.list", goal="list tasks"),
        principal,
        justification="",
    )

    frame = await kernel.invoke(token, principal=principal, args={})
    print(frame.facts)
    print(kernel.explain(frame.action_id))


asyncio.run(main())
```

The README quickstart is exercised in CI; a runnable mirror lives at [`examples/readme_quickstart.py`](examples/readme_quickstart.py).

For a guided walkthrough, see [`docs/tutorial.md`](docs/tutorial.md).

## Security properties

The current design centers on three Weaver invariants:

| Invariant | Property |
|---|---|
| **I-01** | Raw driver output does not enter the default LLM-safe path; the Context Firewall produces a bounded `Frame`. |
| **I-02** | Kernel-mediated execution is authorized and auditable. |
| **I-06** | Capability tokens bind the principal, capability and constraints and expire. |

Important hardening work takes priority over speculative surface growth. The current critical path includes:

- #181 — unknown MCP tools must not silently receive permissive authority;
- #170 — invocation-time rate-limit / token-use semantics;
- #226 — multi-worker consistency;
- #263 + #173 — MCP v2 migration and real interoperability testing;
- #103 — authentication/secrets production hardening;
- #199 + #245 — executable invariants and adversarial/property tests;
- #258 — exact action/transaction binding analysis.

See the gate-driven **[ROADMAP](ROADMAP.md)** for sequencing and kill criteria.

## MCP

MCP is a strategically important execution surface, but Kernel intentionally does not claim blanket “MCP security.” The supported SDK/protocol envelope must be tested continuously, and unknown tool authority must fail closed before broad MCP-security promotion.

Install MCP support with:

```bash
pip install "weaver-kernel[mcp]"
```

See [`docs/integrations.md`](docs/integrations.md) and the live MCP compatibility/hardening issues (#173, #181, #263) before production use.

## Policy

Kernel ships a deterministic built-in policy engine with READ / WRITE / DESTRUCTIVE safety classes, sensitivity handling and stable denial reason codes.

That engine is a standalone default, **not a requirement that adopters replace their existing IAM**. The roadmap favors a narrow policy-provider/interoperability seam and shared policy contracts where they reduce duplication (#111, #116).

Unknown authority should fail closed. The planned easy-mode experience is **observe → classify → enforce**, not “guess that an unknown tool is safe.”

## Audit and bounded output

Every Kernel-mediated invocation can produce an `ActionTrace`; durable trace stores add tamper-evident hash chaining. The Context Firewall produces bounded `Frame` objects and applies redaction/budget logic before data is returned on the default LLM-safe path.

Audit evidence is not automatically non-repudiation: trust still depends on secret custody, deployment architecture and trace-store integrity. See [`docs/security.md`](docs/security.md).

## Where it fits in the Weaver ecosystem

Each project is independently usable:

| Project | Job |
|---|---|
| **Weaver Kernel** *(this repository)* | Embedded execution enforcement, scoped capability grants, bounded results and action traces. |
| [AgentFence](https://github.com/dgenio/AgentFence) | Out-of-process policy/tool boundary when you cannot or do not want to trust the agent host to mediate every call. |
| [ContextWeaver](https://github.com/dgenio/contextweaver) | Select and compile bounded context/capability visibility for the model. |
| ChainWeaver | Deterministic multi-step execution. |
| [weaver-spec](https://github.com/dgenio/weaver-spec) | Implementation-neutral contracts and conformance work. |

Use Kernel alone when that is all you need. Composition should be a second step, not an onboarding requirement.

## When not to use Weaver Kernel

- You only need a coarse external policy boundary around a third-party host: AgentFence or another gateway may be simpler.
- You cannot ensure sensitive actions cross the embedded Kernel boundary: use a stronger out-of-process enforcement/sandbox boundary.
- You only need prompt/context selection: use ContextWeaver.
- You only need a deterministic scripted workflow with no agentic authorization problem: use a normal workflow engine or ChainWeaver.
- You need mature organization-wide IAM/policy authoring: keep that system and integrate Kernel only where its execution/evidence boundary adds value.

## Project identity

| Surface | Name |
|---|---|
| Product | **Weaver Kernel** |
| GitHub repository | `dgenio/agent-kernel` |
| PyPI | `weaver-kernel` |
| Python import | `weaver_kernel` |
| CLI | `weaver-kernel` |

The historical GitHub slug is intentionally retained for now. A repository rename is not part of the current critical path.

## Documentation

- [Security Contract](docs/security-contract.md)
- [Security Model](docs/security.md)
- [Roadmap](ROADMAP.md)
- [Tutorial](docs/tutorial.md)
- [Architecture](docs/architecture.md)
- [Integrations](docs/integrations.md)
- [Designing capabilities](docs/capabilities.md)
- [Context Firewall](docs/context_firewall.md)
- [Coding-agent security scenario](docs/coding-agent-security.md)

## Development

```bash
git clone https://github.com/dgenio/agent-kernel
cd agent-kernel
pip install -e ".[dev]"
make ci
```

The project enforces strict typing, a ≥90% coverage floor, dependency auditing and CodeQL. Releases include supply-chain metadata described in [`RELEASE.md`](RELEASE.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
