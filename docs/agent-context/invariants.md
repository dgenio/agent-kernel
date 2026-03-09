# Invariants — Agent Context

> Canonical source for hard constraints, forbidden shortcuts, and weaver-spec compliance.
> Referenced from `AGENTS.md`. Consult before any change that could weaken security guarantees.

## Weaver-spec compliance

agent-kernel must conform to [weaver-spec](https://github.com/dgenio/weaver-spec) invariants.
All three are equally critical — there is no priority ordering.

| Invariant | Requirement | Where enforced |
|-----------|-------------|----------------|
| **I-01** | Every tool output must pass through a context boundary before reaching the LLM | `Firewall.transform()` in `firewall/transform.py` |
| **I-02** | Context boundaries must enforce budgets (size, depth, field count) | `Budgets` in `firewall/budgets.py` |
| **I-06** | Tokens must bind principal + capability + constraints; no reuse across principals | `HMACTokenProvider.verify()` in `tokens.py` |

## Forbidden shortcuts — "never do" list

These constraints are non-negotiable. Violating any one silently degrades security.

1. **Never bypass the Firewall.** `RawResult → Frame` transformation is mandatory.
   Raw driver output must never reach the LLM (except via admin `raw` mode, which
   the Firewall itself controls).

2. **Never skip token verification before invocation.** `Kernel.invoke()` always calls
   `verify()` first. Removing or short-circuiting this check defeats confused-deputy
   prevention.

3. **Never allow non-admin principals to get `raw` response mode.** The Firewall
   downgrades `raw` to `summary` for non-admin principals. Any code path that bypasses
   this check leaks unbounded, unredacted data.

4. **Never store secrets in token payloads.** Tokens are HMAC-signed but not encrypted.
   Payload contents are readable by anyone who holds the token.

5. **Never log or print secret key material.** The `AGENT_KERNEL_SECRET` and any
   derived keys must stay out of logs, error messages, and traces.

6. **Never add dependencies without justification.** The dependency list is intentionally
   minimal (`httpx` only). Every new dependency expands the attack surface.

7. **Never register duplicate capability IDs.** The registry raises
   `CapabilityAlreadyRegistered`. Duplicates cause ambiguous routing and policy
   enforcement.

## Security-critical ordering traps

These are subtle correctness hazards where the code is correct today but a careless
change introduces a silent bypass.

### Policy rule ordering
`DefaultPolicyEngine.evaluate()` processes rules sequentially. Adding a new "allow"
rule before sensitivity/justification checks can silently bypass them. Always add
new rules **after** existing sensitivity checks, or verify that the new rule's
position does not short-circuit downstream checks.

### SensitivityTag coverage
`evaluate()` only checks `SensitivityTag` values it knows about. Adding a new tag to
the `SensitivityTag` enum without a corresponding rule in `evaluate()` means the new
tag is **silently ignored** — capabilities tagged with it pass policy without constraint.

**Rule:** When adding a `SensitivityTag`, always add a matching policy rule and test.

## Safe vs. unsafe changes

| Safe | Unsafe |
|------|--------|
| Refactoring driver internals without changing the `Driver` Protocol | Changing the `Driver` Protocol (breaks downstream implementors) |
| Adding a new response mode to the Firewall | Removing the Firewall step from `invoke()` |
| Adding a new policy rule after existing checks | Adding a policy rule before sensitivity checks |
| Adding error subclasses | Raising bare `ValueError`/`KeyError` to callers |

## Update triggers for this file
- A weaver-spec invariant is added, changed, or reinterpreted.
- A new "never do" constraint is discovered through review or incident.
- A new security-critical ordering trap is identified.
