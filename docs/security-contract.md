# Weaver Kernel Security Contract

This page defines the security claim that Weaver Kernel is prepared to make today, the assumptions behind that claim, and the work that must land before stronger claims are made.

The short version is:

> **Weaver Kernel mediates submitted agent actions, applies an authorization decision before the configured driver executes them, bounds the result returned through the Kernel path, and records an auditable action trace. It does not make an LLM trustworthy and it cannot protect execution paths that bypass Kernel mediation.**

## Product boundary

Weaver Kernel is an **embeddable execution-enforcement runtime**. It can use its built-in policy engine, but policy authoring is not intended to be the only or eventual integration model.

A deployment may obtain identity and policy decisions elsewhere:

```text
identity / workload authentication
          ↓
policy decision
(native policy, Cedar/OpenFGA/Auth0/OAP/custom)
          ↓
      Weaver Kernel
(bind authority → enforce → execute → bound result → receipt)
          ↓
      MCP / API / tool
```

The long-term interoperability goal is **bring your identity and policy; enforce the resulting authority consistently at the agent-action boundary**.

## What is enforced on the supported path

For an invocation that is submitted through Kernel:

1. the caller supplies a `Principal`;
2. the requested capability is evaluated by a policy engine;
3. an allowed request receives a signed, expiring `CapabilityToken`;
4. `invoke()` verifies the token and principal before driver execution;
5. driver output is transformed by the Context Firewall before it is returned through the default LLM-safe path;
6. an `ActionTrace` records the mediated execution path and can be inspected with `kernel.explain()` / trace APIs.

Current capability tokens bind at least:

- `principal_id`;
- `capability_id`;
- signed constraints;
- expiry.

Handle expansion separately re-checks the principal and the grant constraints persisted on the handle.

## What is **not** currently claimed

### Complete mediation

Weaver Kernel is an in-process library. If an application, framework, hosted tool, subprocess, SDK or agent can execute the underlying action without going through Kernel, Kernel cannot prevent that bypass.

Therefore integrations must document the execution surfaces they mediate. Do not describe a framework as “secured by Weaver Kernel” when only a subset of its tool surfaces pass through the adapter.

For a stronger process boundary, use an out-of-process control such as AgentFence or another gateway/sandbox in addition to, or instead of, the embedded Kernel.

### Transaction-level / exact-action authorization

The current token contract does **not** yet claim to bind every authorization decision to the complete executable transaction (for example exact normalized arguments, resolved resource identity, run/plan identifier, tool-descriptor digest, pre-state digest, approval receipt, destination and single-use semantics).

That stronger model is being evaluated in #258. Until it lands, describe Kernel tokens as **principal- and capability-scoped grants with signed constraints**, not as cryptographic proof that one exact transaction was authorized.

### Authentication

A `Principal` is authorization input, not proof of identity. The host is responsible for deriving the principal from an authentication mechanism it trusts. A production authentication seam is tracked in #103.

### Sandbox / prompt-injection cure

Kernel policy can constrain mediated actions after a model has made a bad or adversarially influenced decision. It is not a VM/container sandbox, malware detector, prompt-injection cure, model-alignment system, or proof that the model's reasoning is correct.

### Distributed consistency

Some enforcement and audit state is process-local today. Multi-worker deployments can fragment revocation state, handles, rate-limit state, budgets and traces. The exact consistency model and mitigation are tracked in #226.

## Fail-closed requirements for advertised integrations

A security integration is not ready to be advertised as a supported path unless all of the following hold:

- unknown/unclassified tools do not silently receive permissive authority (#181);
- the documented rate-limit semantics match the execution path, including token reuse (#170);
- the integration's supported protocol/SDK versions are continuously tested against real implementations (#173, #263);
- the integration publishes a mediation/coverage matrix;
- policy denials and execution failures remain auditable without exposing secrets;
- the README and released package describe the same supported behavior.

## Policy interoperability

The built-in policy engine is a useful standalone default and a conformance target. It should not force adopters to replace mature IAM systems.

The preferred architecture is to keep the enforcement contract stable while allowing policy decisions to come from:

- the native Weaver Kernel policy engine;
- a shared Weaver policy contract / AgentFence-compatible policy (#111, #116);
- external authorization systems through a narrow provider interface;
- portable authorization artifacts if an external standard gains adoption.

This avoids coupling Kernel adoption to a bet on which policy ecosystem wins.

## Action-binding direction

A stronger grant should be able to express and, where applicable, cryptographically bind authority such as:

```text
principal
capability / action
resolved resource identity + provenance
normalized argument constraints or exact-argument digest
run / approved-plan identity
approval reference
expiry
use count / single-use semantics
policy decision reference
```

The important property is monotonicity: execution must not widen the authority that was actually approved.

This direction should reuse portable contracts from `weaver-spec` / IntentFlow where they are suitable rather than inventing a second incompatible transaction language inside Kernel.

## Evidence contract

An `ActionTrace` is operational evidence about the Kernel-mediated path. It should let a reviewer answer:

- which principal requested the action;
- which capability was involved;
- which policy decision/reason applied;
- whether the action executed or was denied;
- which driver performed the action;
- what bounded result metadata was returned;
- what follow-up expansion or approval events occurred.

A trace is not automatically non-repudiation. Trust depends on secret custody, trace-store integrity and deployment architecture; see [security.md](security.md).

## Security-claim vocabulary

Prefer precise language:

- **Good:** “The mediated tool call was denied before the configured driver executed.”
- **Good:** “Kernel verified a principal-scoped capability grant before this invocation.”
- **Good:** “The default Kernel return path produced a bounded `Frame` rather than returning the raw driver result.”
- **Avoid:** “The model was compromised but the data could not leave.”
- **Avoid:** “This secures OpenAI/LangChain/MCP” without a surface-by-surface coverage statement.
- **Avoid:** “Production hardened” until the production-hardening gates are met.

## Current hardening gates

The security-critical work that takes precedence over speculative feature growth is:

- #181 — fail closed for unclassified MCP tools;
- #170 — define/enforce invocation-time rate-limit and token-use semantics;
- #226 — document and address multi-process consistency limitations;
- #263 + #173 — MCP v2 migration and real interoperability testing;
- #103 — production authentication/secrets hardening;
- #199 + #245 — executable invariants and adversarial/property tests;
- #258 — exact action / transaction binding analysis.

See [ROADMAP.md](../ROADMAP.md) for the adoption gates that sequence this work.
