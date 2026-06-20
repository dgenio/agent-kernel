# Designing Capabilities

## Naming conventions

- Use `domain.verb_noun` format: `billing.list_invoices`, `users.get_profile`.
- Prefer fully namespaced IDs (`billing.invoices.list`) over flat ones —
  the registry will infer namespace operations from the dot-segments and
  large ecosystems benefit from being able to list/search per namespace.
- Be specific: prefer `billing.cancel_invoice` over `billing.update`.
- Avoid generic names like `billing.execute` or `api.call`.

## Namespaces and discovery

`CapabilityRegistry` recognises dot-notation namespaces automatically. No
extra registration step is required — `register(Capability(capability_id=
"billing.invoices.list", ...))` is enough to populate the `billing` and
`billing.invoices` namespaces.

```python
registry.list_namespaces()
# ['billing', 'crm']

registry.list_namespace("billing")
# [Capability('billing.invoices.list'), Capability('billing.payments.refund'), …]
```

For large tool ecosystems where eagerly registering hundreds of
capabilities is wasteful, declare a deferred loader. The loader runs at
most once, the first time the namespace is searched, listed, or any
capability under it is fetched via `get()`:

```python
def load_billing() -> list[Capability]:
    return [
        Capability(capability_id="billing.invoices.list", …),
        Capability(capability_id="billing.invoices.create", …),
        Capability(capability_id="billing.payments.refund", …),
    ]

registry.register_namespace(
    "billing",
    description="Billing and invoicing tools",
    loader=load_billing,
)
```

Search ranks matches with a BM25-flavoured scorer that weights
`capability_id` and `tags` higher than `description`, strips a small
stop-word set (`a`, `the`, `please`, …), and offers `offset` for
pagination:

```python
results = registry.search("list invoices", max_results=10, offset=0)
```

Search is deterministic — equal-scoring capabilities are returned in
`capability_id` order — and trips any deferred namespace loader whose
prefix shares a token with the query.

## Granularity

Each capability should map to a single, auditable action with clear side-effects.

**Good:**
- `billing.list_invoices` (READ, no side-effects)
- `billing.send_reminder` (WRITE, sends an email)
- `billing.void_invoice` (DESTRUCTIVE, irreversible)

**Avoid:**
- `billing.do_stuff` (too broad)
- `billing.list_or_update_invoices` (mixed safety classes)

## Safety classes

| Class | Examples | Policy |
|-------|---------|--------|
| READ | list, get, search, summarize | Always allowed |
| WRITE | create, update, send, approve | Justification + writer role |
| DESTRUCTIVE | delete, void, purge, terminate | Admin role only |

## Sensitivity tags

Use `SensitivityTag.PII` when results may contain: name, email, phone, SSN, address.
Use `SensitivityTag.PCI` when results may contain: card numbers, CVV, bank details.
Use `SensitivityTag.SECRETS` when results may contain: API keys, passwords, tokens.
Use `SensitivityTag.MEMORY` when results are durable agent memory (project notes,
session handoff, learned context). Pair it with the `memory.read` / `memory.write` /
`memory.forget` capability IDs to activate the policy rules and audit-trace redaction
described in [`docs/security.md#memory-actions`](security.md#memory-actions).

Always pair sensitivity tags with `allowed_fields` to restrict which fields are returned
to non-privileged callers.

## Tags

Add descriptive tags to improve keyword matching:

```python
Capability(
    capability_id="billing.list_invoices",
    tags=["billing", "invoices", "list", "finance", "accounts receivable"],
    ...
)
```

## Dry-run mode

`Kernel.invoke(..., dry_run=True)` verifies the token and resolves the route
plan but **never calls the driver**. Use it to validate that a principal can
invoke a capability, inspect what a driver *would* receive, or run policy
checks in CI without live tool backends.

```python
result = await kernel.invoke(
    token,
    principal=principal,
    args={"operation": "billing.list_invoices", "max_rows": 5},
    response_mode="summary",
    dry_run=True,
)
# result: DryRunResult(
#   capability_id="billing.list_invoices",
#   principal_id="user-001",
#   policy_decision=PolicyDecision(allowed=True, ...),
#   driver_id="billing",
#   operation="billing.list_invoices",
#   resolved_args={"operation": "billing.list_invoices", "max_rows": 5},
#   response_mode="summary",
#   budget_remaining=None,
#   estimated_cost="low",
# )
```

Three rules govern dry-run behaviour — keep them in sync with the real-invoke
path if you change either:

1. **Token verification still runs.** Expired, revoked, or scope-mismatched
   tokens raise `TokenExpired` / `TokenRevoked` / `TokenInvalid` /
   `TokenScopeError` exactly as they would at real-invoke. Policy is *not*
   re-evaluated at invoke time — the granting policy decision is encoded in
   the token at `grant_capability`.
2. **Operation resolution mirrors drivers.** `DryRunResult.operation` is
   computed the same way every driver computes it:
   `str(args.get("operation", capability_id))`. Always use `args["operation"]`
   when you need a fixed operation; otherwise the dry-run operation is the
   capability ID, matching what the driver would see.
3. **Raw-mode admin gate mirrors the Firewall.** Non-admin principals never
   get `response_mode="raw"` at real-invoke (the Firewall downgrades it to
   `"summary"` — see `firewall/transform.py`). Dry-run downgrades the same
   way, so non-admin callers cannot probe for raw-mode availability via
   `DryRunResult`.

The driver's `execute()` is never called in dry-run, so the mode is free of
side effects regardless of driver type (`InMemoryDriver`, `HTTPDriver`,
`MCPDriver`). `DryRunResult.budget_remaining` is currently always `None`; the
field is reserved for a future cross-invocation budget mechanism.

## Declarative policies

`DeclarativePolicyEngine` is an alternative to `DefaultPolicyEngine` that
loads rules from a YAML or TOML file (or a plain dict). Rules are evaluated
top-down, first-match-wins; if no rule matches, the policy's `default` action
applies (`"deny"` unless overridden).

```python
from pathlib import Path
from weaver_kernel import DeclarativePolicyEngine, Kernel

# YAML or TOML — both formats are interchangeable.
policy = DeclarativePolicyEngine.from_yaml(Path("examples/policies/default.yaml"))

# Or build entirely in-memory:
policy = DeclarativePolicyEngine.from_dict({
    "default": "deny",
    "rules": [
        {"name": "allow-read", "action": "allow",
         "match": {"safety_class": ["READ"], "sensitivity": ["NONE"]}},
        # ...
    ],
})

kernel = Kernel(registry=registry, policy=policy)
```

A rule's `match` block supports `safety_class`, `sensitivity`, `roles`
(ANY-of), `attributes` (ALL-of, with `"*"` meaning "attribute must be
present"), and `min_justification` (minimum stripped length). On `allow`, the
rule's `constraints` are merged into the resulting `PolicyDecision`. On
`deny`, `reason` is embedded in the raised `PolicyDenied`.

The DSL has no negation/missing-attribute operator today, so a policy that
should deny "when an attribute is missing" should be expressed as an allow
rule requiring the attribute paired with `default: deny`. See
[`examples/policies/default.yaml`](../examples/policies/default.yaml) for a
worked example.

`pyyaml` and `tomli` are **optional** — they live behind the `[policy]`
extra. `import weaver_kernel` always works; calling `from_yaml` / `from_toml`
without the parser installed raises `PolicyConfigError` with an install hint.

## Denial explanations

When a capability call is denied, `Kernel.explain_denial(request, principal,
justification="")` returns a structured `DenialExplanation` describing
**every** unmet condition (not just the first one), so the caller can see the
full remediation path:

```python
explanation = kernel.explain_denial(
    CapabilityRequest(capability_id="billing.update_invoice", goal="..."),
    principal,
    justification="too short",
)
# explanation.denied == True
# explanation.rule_name == "write-min_justification"
# explanation.failed_conditions == [FailedCondition(condition="roles", required=[...]), ...]
# explanation.remediation == ["Add 'writer' or 'admin' role to ...", "Provide ..."]
# explanation.narrative == "Request for 'billing.update_invoice' by '...' would be denied: ..."
```

Both built-in engines support `explain()`. If you bring a custom policy
engine that implements only `PolicyEngine.evaluate`, `explain_denial` raises
`AgentKernelError` with guidance — implement the `ExplainingPolicyEngine`
protocol to enable structured explanations.

## Validating a policy change with replay (#213)

A policy edit is the highest-blast-radius change in the system: one rule can
silently widen access or break every agent. The replay harness re-evaluates a
corpus of recorded decisions against a *candidate* policy and reports the
decision diff, so you get a deterministic "what would have changed" answer before
deploying.

```python
from weaver_kernel import DefaultPolicyEngine, record_decision, replay

baseline = DefaultPolicyEngine()
# Build a corpus (a real one would come from historical traffic).
records = [
    record_decision(baseline, request, capability, principal, justification="..."),
    # ...
]

diff = replay(records, candidate_engine)
assert diff.empty          # replaying against the same engine → no flips
for flip in diff.flips:    # allow_to_deny | deny_to_allow | reason_code_change
    print(flip.record.capability.capability_id, flip.kind,
          flip.baseline_reason_code, "->", flip.candidate_reason_code)
```

Determinism and fidelity:

- Output order is the input record order; replaying records against the engine
  that produced them yields `diff.empty`.
- Rate-limit decisions are replay-order-sensitive (the default engine's limiter is
  stateful), so flips involving `DenialReason.RATE_LIMITED` are surfaced in
  `diff.rate_limited` rather than `diff.flips`.
- Replay validates **policy structure** (role/justification/constraint rules), not
  argument-dependent rules whose inputs the audit trail redacts.

Runnable recipe: [`examples/trace_replay_demo.py`](../examples/trace_replay_demo.py).
This complements shadow mode (live-traffic comparison) and the fixture-based
policy testing framework with real-traffic, pre-deployment coverage.
