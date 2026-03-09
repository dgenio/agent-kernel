# Architecture — Agent Context

> Canonical source for architectural intent and design tradeoffs.
> For component API details, see [../architecture.md](../architecture.md).
> For hard invariants, see [invariants.md](invariants.md).

## Intent

agent-kernel is a **capability-based security kernel** for AI agents operating in large
tool ecosystems (MCP, HTTP APIs, internal services). It sits between the LLM and raw tool
execution, enforcing least-privilege, confused-deputy prevention, and context firewalling.

The architecture optimizes for:
- **Security over convenience** — every capability invocation requires a scoped, signed token.
- **Bounded LLM context** — the Firewall always transforms raw output into a bounded Frame.
- **Auditability** — every action is traced; no silent execution.
- **Determinism** — no randomness in matching, routing, or summarization.

## Major boundaries

1. **Kernel ↔ Drivers**: The Kernel never exposes raw driver output. The Firewall always
   mediates. This boundary enforces weaver-spec I-01.

2. **PolicyEngine ↔ Kernel**: Policy decisions are made *before* token issuance, not at
   execution time. The token carries the approved constraints. This prevents
   time-of-check/time-of-use gaps.

3. **TokenProvider ↔ Kernel**: Tokens are verified on every `invoke()`, not just at
   issuance. This prevents replayed, expired, or tampered tokens from executing.

4. **Registry ↔ Router**: The registry owns capability metadata; the router maps
   capabilities to drivers. They are deliberately separate so that routing changes
   don't affect policy or capability definitions.

## Key tradeoffs

| Decision | Why | Consequence |
|----------|-----|-------------|
| Tokens signed, not encrypted | Simplicity; avoids key management complexity | Payloads are readable — never store secrets in them |
| Keyword-based capability search | Deterministic; no external service dependency | Less flexible than semantic search; relies on good tagging |
| Firewall is mandatory | Prevents accidental context blowup and data leakage | All output is bounded; debugging requires admin `raw` mode |
| Single dep (`httpx` only) | Minimal attack surface for a security kernel | Adding a dependency requires justification |

## Things not to simplify

- **Do not bypass the Firewall** to "improve performance." It enforces I-01 and I-02.
- **Do not merge PolicyEngine and TokenProvider.** Policy decides; tokens carry the
  decision. Merging them creates confused-deputy vulnerabilities.
- **Do not make the Router stateful.** Routing is a pure mapping. Stateful routing
  introduces ordering dependencies and non-determinism.
