# Security Model

Start with the concise [Security Contract](security-contract.md). This page gives the implementation-level threat model and operational caveats behind that contract.

## Threat model

| Threat | Current mitigation |
|---|---|
| Tool-space interference | Capability registry + policy gate before Kernel-mediated execution |
| Confused deputy / cross-principal token reuse | Tokens bind `principal_id`; verification rejects a different principal |
| Token tampering | HMAC-SHA256 signature verification |
| Token replay after expiry | Expiry is checked during token verification |
| Raw tool output reaching the default LLM-safe path | `RawResult` is transformed by the Context Firewall into a bounded `Frame` |
| PII / PCI leakage | Firewall redaction + allowed-field enforcement on supported egress paths |
| Deeply nested secret leakage | Redaction fails closed at the configured depth boundary; nested containers are elided rather than returned verbatim |
| Handle expansion escaping the grant | Handle expansion re-checks principal binding and persisted grant constraints |
| Sensitive arguments/results leaking into audit | Trace arguments/errors pass through redaction; result summaries are built from post-firewall data rather than raw driver output |
| Privilege escalation through WRITE / DESTRUCTIVE classes | Policy engine applies role / justification rules |
| Audit mutation | Durable trace stores can use HMAC hash chaining to make mutation/interior deletion/reordering evident |

The important qualifier is **Kernel-mediated**. Weaver Kernel is an in-process library and cannot protect an execution path that bypasses it.

## Capability-token scope

A current `CapabilityToken` binds:

- `capability_id` — which capability is authorized;
- `principal_id` — the authorization subject;
- `constraints` — signed scope such as row/field limits where used;
- `expires_at` — the validity window.

Changing a signed field invalidates the HMAC signature.

### Current boundary of the token claim

The current format should be described as a **principal- and capability-scoped grant with signed constraints**, not proof that one exact executable transaction was authorized.

Exact binding to all normalized arguments, resolved resource identity/provenance, run/plan identity, approval receipt, tool-descriptor digest, pre-state and single-use semantics is an active design topic (#258). See [security-contract.md](security-contract.md).

## Principal identity and authentication

`Principal` is authorization input supplied by the host. Kernel does not currently prove that the asserted principal corresponds to a human, workload or authenticated session.

The host must derive the principal from a trusted authentication mechanism. A production authentication/provider seam is tracked in #103.

## Confused-deputy prevention

A token issued to one principal cannot be reused by a different principal because verification checks the principal binding.

Handles follow the same principle. A stored handle carries the original grant principal; expansion requires a matching principal and treats an omitted/mismatched identity as `HandleConstraintViolation` / `HANDLE_PRINCIPAL_MISMATCH`.

## Handle expansion boundary

`kernel.expand()` does not re-run the original policy decision, but it re-applies the grant constraints persisted with the handle.

| Constraint | Expansion behavior |
|---|---|
| `max_rows` | Requests above the cap are rejected or clamped according to the API path. |
| `allowed_fields` | Out-of-scope fields are rejected; default projection cannot reveal disallowed fields. |
| `scope` | Stored scope is merged into the query and conflicting scope is rejected. |
| `principal_id` | A different/omitted principal is rejected. |

Stable reason codes should be used by integrations instead of parsing human-readable messages.

## Memory actions

Capabilities tagged for durable memory receive additional policy treatment. Sensitive memory reads and memory writes require explicit roles, and payload-like memory fields are stripped from `ActionTrace.args` so the audit trail does not become a durable memory-content sink.

## Context Firewall

The Context Firewall is the boundary between a raw driver result and the default LLM-safe representation.

It provides:

- bounded `Frame` output;
- field / row budgets;
- redaction;
- handle-based expansion under persisted constraints;
- streaming redaction with bounded overlap handling.

Redaction is defense in depth, not a substitute for data governance. The built-in detector is heuristic and can miss domain-specific or adversarial representations.

Streaming redaction also has a bounded overlap/memory trade-off: sufficiently pathological secrets or patterns split outside the supported overlap assumptions may evade heuristic detection. Do not advertise regex redaction as a formal confidentiality guarantee.

## MCP discovery and tool classification

MCP tool annotations are hints, not a trusted authorization statement.

Explicit operator mappings (`safety_class_map`) take precedence over server-provided hints. `destructiveHint=True` wins over `readOnlyHint=True` when both are present. Tools with neither usable hints nor an explicit mapping are **rejected by default** (#181) rather than silently becoming `READ`.

For full precedence rules and migration from pre-#181 behavior, see
[mcp-safety-classification.md](mcp-safety-classification.md).

MCP SDK/protocol compatibility is also a live support boundary (#263, #173). Check the supported dependency range before relying on the integration.

## Rate limiting and token reuse

The default policy includes per-principal/per-capability sliding-window limits, but the exact relationship between grant-time evaluation and repeated invocation of a reusable token is being hardened in #170.

Do not describe the current rate limiter as a complete runaway-agent control until invocation-time semantics are explicitly enforced and tested.

## Multi-process / multi-worker deployments

Several stateful components are process-local today, including parts of:

- revocation state;
- rate limiting;
- handles;
- budgets;
- trace storage (unless a shared durable store is configured).

A horizontally scaled deployment can therefore have different security/operational semantics from a single process. In particular, token signature verification is stateless while revocation and some enforcement state are not, which can create non-obvious divergence.

The consistency model and mitigation architecture are tracked in #226. High-assurance deployments should understand this limitation before scaling worker count.

## Audit trail and tamper evidence

Kernel records authorization/execution-related events as `ActionTrace` records, including supported invoke, deny and expansion events.

Trace fields are intended to answer questions such as:

- who requested the action;
- which capability was involved;
- why policy allowed/denied it;
- which driver executed;
- what bounded result metadata was produced;
- what follow-up expansion/approval activity occurred.

Durable stores (`SQLiteTraceStore`, `JsonlTraceStore`) can wrap records in an HMAC hash chain. This can detect mutation and broken interior linkage.

### What hash chaining does not prove

- It does not provide non-repudiation when the host controls the signing secret.
- It does not encrypt trace contents at rest.
- Without an independently anchored expected head/length, a self-consistent truncated tail can remain undetectable.
- Deleting the whole local store is not prevented by the chain.

For higher assurance, ship traces to storage with independent retention/integrity controls.

## Security automation

The repository uses CI, strict typing, a coverage floor, dependency auditing and CodeQL. Release artifacts include the supply-chain metadata documented in [`../RELEASE.md`](../RELEASE.md).

These controls improve software assurance; they do not by themselves establish production security suitability.

## Current maturity statement

Weaver Kernel is pre-1.0. The package has moved materially beyond the old “v0.1” wording that previously appeared in this document, but it should **not** be described as fully production-hardened authentication/authorization infrastructure yet.

Known hardening gates include:

- #103 — authentication, secrets and production-hardening criteria;
- #181 — fail-closed MCP classification;
- #170 — invocation-time rate-limit/token-use semantics;
- #226 — distributed consistency semantics;
- #263 + #173 — MCP v2 and real interoperability;
- #199 + #245 — executable invariants and adversarial/property testing;
- #258 — exact action/transaction binding.

See [`../ROADMAP.md`](../ROADMAP.md) for sequencing.

## Deployment checklist

Before relying on Kernel in a security-sensitive deployment:

1. set and protect a strong `WEAVER_KERNEL_SECRET`; do not rely on the generated development secret;
2. derive `Principal` from authenticated identity/workload context;
3. explicitly classify high-risk/unknown tools;
4. review which framework execution surfaces actually pass through Kernel;
5. test allow **and deny** paths for your own policy;
6. verify constraints on the exact resources/arguments that matter to your tools;
7. choose durable trace storage and retention appropriate to the threat model;
8. understand multi-worker state semantics before horizontal scaling;
9. pin/test the MCP/other SDK versions you deploy;
10. read [security-contract.md](security-contract.md) and do not broaden its claims in downstream documentation.
