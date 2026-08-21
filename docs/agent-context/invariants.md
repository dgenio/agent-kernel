# Invariants — Agent Context

> Canonical source for hard constraints, forbidden shortcuts, and weaver-spec compliance.
> Referenced from `AGENTS.md`. Consult before any change that could weaken security guarantees.

## Weaver-spec compliance

Weaver Kernel must conform to [weaver-spec](https://github.com/dgenio/weaver-spec) invariants.
All three are equally critical — there is no priority ordering.

| Invariant | Requirement | Where enforced |
|-----------|-------------|----------------|
| **I-01** | Every tool output must pass through a context boundary before reaching the LLM-safe path | `Firewall.transform()` in `firewall/transform.py`, called by `kernel/_invoke.py` and streaming paths |
| **I-02** | Every execution must be authorized and auditable (CapabilityToken validated before execution; ActionTrace recorded for the mediated run) | `HMACTokenProvider.verify()` in `tokens.py`; `Kernel.invoke()` / `kernel/_invoke.py`; trace stores |
| **I-06** | Tokens must bind principal + capability + constraints; no reuse across principals | `CapabilityToken` signed payload + `HMACTokenProvider.verify()` in `tokens.py` |

> **Budget enforcement** (size, depth, field count via `Budgets` in `firewall/budgets.py`) is an
> implementation constraint that strengthens I-01. It has no separate invariant number in weaver-spec.

## Executable invariant suite

The named architecture-level regression suite is [`tests/test_invariants.py`](../../tests/test_invariants.py).
It contains at least three black-box/component tests for each current Weaver invariant:

- **I-01:** non-admin raw downgrade/redaction, signed allowed-field projection, and handle-only payload isolation;
- **I-02:** invalid authority cannot reach a driver, successful execution has an explainable trace, and driver failure is still audited;
- **I-06:** cross-principal rejection, cross-capability rejection, and signature failure after constraint widening.

These tests intentionally overlap some specialist suites (`test_firewall_boundary.py`, `test_policy_properties.py`, token tests). The overlap is deliberate: an architectural invariant should fail in a file whose name makes the broken promise obvious during review.

Run only the named suite with:

```bash
pytest -q tests/test_invariants.py
```

Property-based/adversarial coverage remains in `tests/test_policy_properties.py`; the named suite is the compact executable specification, not a replacement for deeper fuzz/property testing.

## Forbidden shortcuts — "never do" list

These constraints are non-negotiable. Violating any one silently degrades security.

1. **Never bypass the Firewall.** `RawResult → Frame` transformation is mandatory.
   Raw driver output must never reach the LLM-safe path (except via admin `raw` mode,
   which the Firewall itself still processes/redacts).

2. **Never skip token verification before invocation.** `Kernel.invoke()` always calls
   `verify()` first. Removing or short-circuiting this check defeats confused-deputy
   prevention.

3. **Never allow non-admin principals to get `raw` response mode.** The Firewall
   downgrades `raw` to `summary` for non-admin principals. Any code path that bypasses
   this check leaks unbounded or inappropriate data.

4. **Never store secrets in token payloads.** Tokens are HMAC-signed but not encrypted.
   Payload contents are readable by anyone who holds the token.

5. **Never log or print secret key material.** The `WEAVER_KERNEL_SECRET` and any
   derived keys must stay out of logs, error messages, and traces.

6. **Never add dependencies without justification.** The dependency list is intentionally
   minimal (`httpx` + `pydantic` — see [`AGENTS.md`](../../AGENTS.md) for the canonical
   dependency policy). Every new dependency expands the attack surface.

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

### Invoke-time enforcement placement
Argument-constraint enforcement (#183) and the optional per-invocation rate limit
(#170) run in `Kernel.invoke`/`Kernel.invoke_stream` **after** `verify()` and
**before** the driver runs or budget is reserved (`kernel/_constraints.py`). A
violation on the real path records a failure `ActionTrace` before raising, so I-02
holds for denied executions; `dry_run=True` evaluates the same checks for parity
but records no rate-limit usage and writes no trace. Both single-shot and
streaming entry points must call `run_pre_invoke_checks` — a new execution entry
point must call it too, or it silently bypasses argument scoping and rate limits.

### Dry-run response-mode parity

`Kernel.invoke(dry_run=True)` reports the response mode the caller would actually
get at real-invoke time. The Firewall downgrades `raw` to `summary` for non-admin
principals, so dry-run must mirror that downgrade — otherwise a non-admin caller
can probe/assume raw-mode availability they will never actually receive. The same
applies to `operation`: dry-run resolves it the same way drivers do
(`args.get("operation", capability_id)`).

**Rule:** Any code path that reports a response mode or driver operation back to the
caller must apply the same admin gate / resolution rule the real-invoke path uses,
including dry-run, mock, and test paths.

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
- The named invariant suite changes which behavior is treated as architecturally load-bearing.
