# Weaver Kernel Roadmap

This roadmap is deliberately **gate-driven, not calendar-driven**. Weaver Kernel should not advance because an internal backlog exists; it should advance when the previous product and security hypothesis survives external use.

The current strategic thesis is:

> **Authorize elsewhere if you want. Weaver Kernel enforces narrowly scoped authority at the agent-action boundary and leaves evidence of what ran.**

The built-in policy engine remains a first-class standalone option. The project should not require adopters to replace mature identity or authorization systems.

## Operating rules

1. Security-contract gaps outrank surface-area growth.
2. External adopter evidence outranks internally imagined demand.
3. Unknown authority fails closed on advertised security paths.
4. Framework integrations publish exactly which execution surfaces they mediate.
5. Main, released package and documentation should describe the same product.
6. Prefer interoperability with identity/policy ecosystems over competing with all of them.
7. Keep speculative work documented, but do not let it consume the critical path.

## Gate 0 — Falsify the wedge

**Question:** Is there a real problem that native framework permissions and existing authorization products do not already solve well enough?

Work:

- compare Kernel against native OpenAI/LangChain-style controls and at least one mature IAM/policy system;
- compare against agent-specific authorization systems rather than assuming the category is empty;
- integrate the current Kernel into three realistic applications without changing their architecture more than necessary;
- test at least two candidate beachheads (coding agents and application/workflow agents);
- record what users still need after existing controls are enabled.

Exit condition:

- three independent developers can explain, in their own words, why they would use Kernel rather than only their framework's native permissions or an ordinary authorization check.

If this condition is not met, reposition before adding features.

## Gate 1 — Define the security contract

**Question:** Can we state exactly what Kernel protects without hidden caveats?

Work:

- maintain [`docs/security-contract.md`](docs/security-contract.md) as the concise claim surface;
- define complete-mediation assumptions and non-guarantees;
- decide the target for exact action/resource/argument binding (#258);
- define the relationship among identity, policy decision, capability grant, invocation and `ActionTrace`;
- add coverage matrices for every advertised framework/protocol integration.

Exit condition:

- the security promise fits in five precise sentences and a reviewer can map each sentence to executable tests or explicitly documented assumptions.

## Gate 2 — Close supported-path blockers

**Question:** Are there known fail-open or misleading semantics on the path we advertise?

Critical work:

- #181 — require deliberate classification of unknown MCP tools;
- #170 — resolve invocation-time rate-limit/token-reuse semantics;
- #226 — make the multi-worker consistency model explicit and choose a mitigation path;
- #263 — deliberately support MCP Python SDK v2;
- #173 — test MCP against real/reference servers;
- #103 — harden authentication/secrets claims;
- #199 and #245 — executable invariants + adversarial/property tests;
- #219 — ensure policy decisions and explanations cannot drift.

Exit condition:

- no known fail-open issue remains on the advertised path;
- protocol/version support is continuously tested;
- production limitations are visible before integration, not buried after it.

## Gate 3 — One exceptional on-ramp

**Question:** Can an adopter get value without adopting the entire internal architecture?

Primary work:

- #104 — drop-in middleware/wrapper path;
- support an **observe → classify → enforce** migration mode rather than unsafe optimistic auto-classification;
- build one generic Python-callable integration and one framework-native integration exceptionally well before multiplying adapters;
- make denials actionable (#221) where this improves the agent loop without leaking policy information;
- keep the full registry/token/driver API as the advanced path.

Exit condition:

- a stranger reaches a correctly denied action and an inspectable trace without maintainer help;
- unknown/unclassified actions cannot accidentally become permissive in the easy path.

## Gate 4 — Prove rather than claim

**Question:** Can a third party reproduce both the security benefit and the usability cost?

Benchmark dimensions:

- unauthorized-action success rate;
- authorized-task completion rate;
- false-deny rate;
- unmediated/bypass surfaces;
- policy/configuration effort;
- p50/p95 enforcement latency;
- audit completeness;
- cross-framework decision consistency;
- scope/attenuation correctness where supported.

Use the coding-agent scenario in #253 only if Gate 0 validates it as the best wedge.

Exit condition:

- a third party can clone a benchmark and reproduce the advertised claims without private infrastructure or maintainer interpretation.

## Gate 5 — Establish external trust

**Question:** Would a security-conscious team trust this component on the boundary it claims to own?

Sequence:

1. external architecture/threat-model review;
2. fix findings and update the contract;
3. stabilize the advertised path;
4. code-level security review/audit;
5. publish findings and remediations.

Exit condition:

- supported guarantees, limitations and review findings are public and materially consistent with the implementation.

## Gate 6 — Distribution through interoperability

**Question:** Is discovery happening outside the maintainer's own GitHub ecosystem?

Work:

- upstream integrations/examples where framework maintainers accept them;
- accept external policy decisions through a narrow provider seam rather than forcing policy migration;
- interoperate with shared Weaver/AgentFence policy contracts (#111, #116);
- prefer compatibility with successful external authorization standards over inventing an incompatible one;
- publish concrete technical case studies and reproducible comparisons.

Exit condition:

- at least three independent downstream repositories use Kernel;
- at least one meaningful external contributor has landed work;
- at least one external ecosystem/framework/security resource points users to Kernel for a specific supported job.

## Gate 7 — Expand only when pulled

Candidate work that is valuable **only after** the supported path has external pull:

- remote/sidecar Kernel (#227);
- A2A driver (#130);
- cross-language verifier/token wire ecosystem (#228);
- packaged driver SPI/plugin ecosystem (#190);
- browser playground (#146);
- mission-control/activity-event surfaces (#240, #243, #255);
- domain-specific capability profiles (#248, #252, #257);
- adaptation/session-learning controls (#254);
- broader federation/delegation/token-format work (#129, #224).

These issues can remain open as research options, but they should not outrank Gates 0–6 without external adopter evidence or a security dependency.

## Kill / reposition criteria

Radically change the current thesis if, after deliberately testing it:

1. developers consistently find native framework permissions sufficient;
2. Kernel cannot provide meaningful enforcement beyond an ordinary middleware callback;
3. exact-action binding requires an API too complex for the value it provides;
4. external security reviewers conclude that the in-process enforcement model adds little assurance;
5. the project cannot obtain three genuinely independent downstream users despite hands-on integration support;
6. users consistently prefer an out-of-process AgentFence/gateway boundary rather than embedded enforcement.

The goal is not to preserve the current architecture. The goal is to discover and build the smallest durable open-source enforcement layer that users actually trust and adopt.
