# contextweaver + agent-kernel: policy before action

`contextweaver` and `agent-kernel` solve adjacent parts of the same runtime
problem and are designed to compose:

- **`contextweaver`** narrows *what the model sees* — it compiles context and
  produces a shortlist of candidate tool cards for a goal.
- **`agent-kernel`** enforces *what the agent may do* — capabilities, policy,
  HMAC tokens, the context firewall, and the audit trace.

The contract between them is simple and worth stating plainly:

> **Routing is advisory. Selection is not permission.** A capability appearing
> on a contextweaver shortlist does not authorize it. Every selected action
> still flows through the full agent-kernel pipeline
> (policy → token → invoke → firewall → trace) before anything executes.

This page describes the reference flow. The runnable companion is
[`examples/contextweaver_policy_flow.py`](../../examples/contextweaver_policy_flow.py),
which uses synthetic data only and runs offline (it does **not** depend on
`contextweaver`).

## The flow

```
goal
  │
  ▼
contextweaver        →  tool-card shortlist (advisory candidate set)
  │
  ▼
host / model selects an intended action
  │
  ▼
agent-kernel         →  grant_capability()  →  policy decision
  │                        │
  │                        ├─ allow   → invoke() → firewall → Frame + ActionTrace
  │                        ├─ ask     → recoverable denial; host confirms, retries
  │                        └─ deny    → terminal denial; host must not retry
  ▼
ActionTrace (audit)
```

1. **contextweaver** builds a small candidate/tool-card shortlist for the goal.
   The shortlist is deliberately permissive — it may include capabilities the
   current principal is not allowed to use.
2. The host (or model) selects an intended action from the shortlist.
3. **agent-kernel** evaluates that action against capability/policy rules.
4. Only approved actions proceed to execution; the rest are surfaced as
   `ask`/confirm or `deny`.

## Three outcomes on a binary policy

agent-kernel's `PolicyDecision` is binary (`allowed: bool`) — there is no
dedicated "ask" verdict. The three host-level outcomes are derived from the
stable `reason_code` on a denial:

| Outcome | How it arises | Stable signal | Host behavior |
|---|---|---|---|
| **allow** | The principal satisfies policy. | `grant_capability()` returns a grant; `invoke()` returns a `Frame`. | Proceed; the action is audited. |
| **ask / confirm** | A WRITE action — or a DESTRUCTIVE action the principal is *otherwise authorized for* — is missing its justification. | `PolicyDenied` with `reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION`. | *Recoverable.* Prompt the human to confirm and supply a justification, then re-grant. |
| **deny** | The principal lacks a required role (or another non-recoverable rule fails). | `PolicyDenied` with e.g. `reason_code == DenialReason.MISSING_ROLE`. | *Terminal.* Do not retry as-is; surface remediation from `Kernel.explain_denial()`. |

Treating a missing justification as `ask` is the natural mapping: the
`DefaultPolicyEngine` already requires a justification of at least 15 characters
for WRITE/DESTRUCTIVE capabilities, so "ask the human to confirm and explain"
is exactly what unblocks the call. A missing role, by contrast, cannot be
satisfied by confirmation and is terminal for that principal.

Note the ordering: role checks run **before** the justification check, so the
`ask` outcome is only reachable once the principal already satisfies the role
requirement. For the DESTRUCTIVE `tickets.delete` below, the support agent lacks
`admin`, so it surfaces as a terminal `missing_role` `deny` regardless of
justification — the example never reaches `ask` for that capability.

## Why the shortlist is not a grant

In the example, contextweaver shortlists `docs.search` (READ),
`tickets.update_status` (WRITE), **and** `tickets.delete` (DESTRUCTIVE) for a
support-agent goal. The agent principal holds `["reader", "writer"]` but not
`admin`, so `tickets.delete` is denied at grant time even though it was
"routed". This is the whole point: context selection improves relevance; it
never widens authority.

## Mapping to Weaver concepts

- A contextweaver tool card maps to a `Capability` (or its public
  `CapabilityDescriptor`).
- "Selecting an action" maps to building a `CapabilityRequest` (carry the
  machine-readable `intent` and `scope` so declarative policies can match
  without parsing free text).
- Enforcement is `Kernel.grant_capability()` followed by `Kernel.invoke()`;
  the resulting `ActionTrace` satisfies weaver-spec invariant **I-02**
  (every execution is preceded by a policy decision and followed by a trace).

## Related

- `examples/contextweaver_policy_flow.py` — runnable, offline.
- [contextweaver](https://github.com/dgenio/contextweaver)
- [weaver-spec](https://github.com/dgenio/weaver-spec)
