# Deployment consistency model

Weaver Kernel is an **in-process enforcement runtime**, not a distributed authorization service. Some state is deliberately local to a Kernel/process unless the deployment supplies a shared backend.

This matters because signed capability tokens are partly stateless while revocation, rate limiting, handles and other runtime state can be local. A multi-worker deployment can therefore have different semantics from a single process even when every worker uses the same signing secret.

The current behavior is pinned by [`tests/test_multi_worker_consistency.py`](../tests/test_multi_worker_consistency.py).

## Current matrix

| Component | Default state | Two workers sharing the same secret | Consequence |
| --- | --- | --- | --- |
| capability-token signature verification | stateless HMAC | token issued by A verifies in B | expected and useful |
| token revocation | in-memory store unless replaced | revoking in A does not revoke in B | revocation is not globally consistent by default |
| rate-limit windows | in-memory | each worker has an independent window | an effective deployment-wide limit can scale with worker count |
| handles / expanded results | in-memory `HandleStore` | handle created in A is unknown in B | requests that move workers cannot expand that handle |
| in-memory traces | process-local | each worker sees its own trace store | audit history fragments unless a shared/durable store is used |
| budget/runtime counters | process-local where backed by in-memory state | counters can diverge | deployment-wide budgets require a shared coordination model |

## Reproducible evidence

The test suite demonstrates four load-bearing facts through public/component APIs:

1. two `HMACTokenProvider` instances with the same secret accept the same valid signed token;
2. revoking that token in worker A does not alter worker B's independent in-memory revocation store;
3. two `RateLimiter` instances have independent windows for the same logical principal/capability key;
4. two `HandleStore` instances do not share handle payloads.

Run:

```bash
pytest -q tests/test_multi_worker_consistency.py
```

These tests are intentionally documentation-as-code: if the implementation changes, the deployment claim must change with it.

## Supported deployment guidance today

### Single process

A single process gives the clearest semantics for the default in-memory stores. It is the easiest deployment profile to reason about when evaluating the library.

### Multiple workers with only a shared signing secret

Do **not** interpret a shared `WEAVER_KERNEL_SECRET` as shared authorization state. It lets workers verify the same token signatures; it does not by itself synchronize revocation, limits, handles or traces.

If a security requirement depends on immediate global revocation, one deployment-wide rate limit, portable handles or one authoritative audit history, the default independent in-memory stores are insufficient.

### Shared/durable stores

Use an available shared/durable backend where one exists and validate its consistency properties for the deployment. A durable backend solves only the state it actually owns; it should not be described as making every Kernel subsystem distributed automatically.

For example, sharing trace storage does not automatically share rate-limit windows or handles.

## Architectural decision before a sidecar

The existence of process-local state does **not** by itself justify building a remote Kernel service.

The sequence should be:

1. identify which guarantees real adopters need across workers;
2. determine whether a small shared-store protocol is sufficient;
3. measure the latency/failure/operational cost of shared state;
4. use a sidecar/remote Kernel only if it materially simplifies the required consistency or trust boundary.

This is why the remote-mode proposal (#227) is intentionally lower priority than documenting and validating this consistency model.

## Security claim language

Prefer:

> “With the default in-memory stores, revocation, rate limits and handles are process-local. Signed tokens can verify across workers that share the signing secret.”

Avoid:

> “Workers share Kernel authorization state because they use the same secret.”

Also avoid describing Kernel as a distributed policy service unless the deployed backends and topology actually establish those semantics.

## Follow-up decisions

The evidence here should inform, rather than pre-decide:

- whether revocation needs a first-class shared-store recommendation;
- whether invocation limits need deployment-wide state after #170/PR #259 settles their semantics;
- whether handles should ever be portable across workers or should remain intentionally sticky/local;
- whether audit stores need a recommended production backend;
- whether #227 earns its complexity from actual adopter requirements.

See the [Security Contract](security-contract.md) and [Roadmap](../ROADMAP.md) for the broader product/security gates.
