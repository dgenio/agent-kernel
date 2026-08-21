# Production checklist

Weaver Kernel is pre-1.0 security infrastructure. Treat production readiness as a set of explicit guarantees and deployment choices, not as a single configuration flag.

Start with the [Security Contract](security-contract.md). This checklist covers the operator decisions most likely to invalidate that contract when a development setup becomes a real deployment.

## 1. Establish authenticated principal identity

Kernel authorizes a `Principal`; it does not authenticate that principal for you.

- derive principal identity from an authentication/workload-identity mechanism you trust;
- do not let model-provided text choose `principal_id` or privileged roles directly;
- document whether the principal represents a human user, workload/service, agent instance, or delegated identity;
- test that authentication failure prevents a capability grant from being minted.

Production authentication/provider hardening is tracked in #103/#279.

## 2. Set and protect the HMAC signing secret

Set a strong `WEAVER_KERNEL_SECRET` before production use.

The development fallback is intentionally process-local and random. It is useful for examples because it requires no setup, but:

- tokens signed with it become invalid after restart;
- separate processes generate different secrets;
- local audit-chain signatures use the same secret-resolution path;
- it is not a substitute for managed secret distribution/rotation.

Do not store sensitive payloads inside capability tokens: HMAC provides integrity/authenticity inside the shared-secret trust domain, **not encryption**.

Key rotation and token-lifecycle hardening are tracked in #185 / PR #259.

## 3. Review capability and tool classification

Unknown authority should fail closed.

For MCP and other discovered tool surfaces:

- maintain an operator-reviewed mapping for high-risk tools;
- treat server/framework safety metadata as advisory rather than authoritative;
- verify WRITE/DESTRUCTIVE classifications against actual side effects;
- include paths/resources/destinations in constraints where the action needs narrower authority than the tool name alone expresses.

#181 / PR #277 hardens the MCP default so missing metadata does not silently become READ.

## 4. Test policy with both allow and deny cases

Before deploying a policy:

- test actions that should succeed;
- test adjacent actions that must fail;
- test a different principal attempting to reuse authority;
- test malformed/oversized constraints;
- test approval/escalation paths without granting adjacent authority;
- prefer stable reason codes over parsing human-readable messages.

Run the named invariant suite as part of normal CI:

```bash
pytest -q tests/test_invariants.py
```

Your application should also have integration tests for its own principal/capability/resource semantics.

## 5. Decide token TTL, reuse and revocation semantics deliberately

A long-lived reusable grant is more authority than a short, single-purpose one.

Review:

- token TTL by safety class/use case;
- whether a token should be reusable or single/max-use;
- invoke-time rate limits;
- revocation expectations;
- what must happen when constraints are malformed or cannot be enforced.

Current lifecycle hardening is concentrated in #170/#185 and PR #259. Do not claim stronger invocation-limit or rotation guarantees until the deployed release actually contains that work.

## 6. Verify every security-sensitive execution path is mediated

Kernel protects actions that pass through its enforcement path. It cannot stop a host/framework from calling the underlying tool around it.

For each integration, make a coverage table:

| Execution surface | Goes through Kernel? | Alternative boundary |
| --- | --- | --- |
| Custom function/tool call | yes/no | wrapper/gateway/sandbox |
| Hosted/provider tool | yes/no | provider controls |
| Shell/subprocess | yes/no | execution sandbox/policy |
| MCP call | yes/no | Kernel/AgentFence/gateway |
| Handoff/sub-agent path | yes/no | explicit integration |

Do not publish “framework X is secured by Kernel” unless every relevant execution surface is actually mediated.

## 7. Understand multi-worker consistency before scaling

Sharing `WEAVER_KERNEL_SECRET` lets workers verify the same HMAC signatures; it does **not** automatically share all enforcement state.

Deployment-consistency guidance is still being formalized. In the current design, process-local state can include revocation, rate-limit windows, handles, budgets and traces unless an appropriate shared backend owns that state.

If your guarantee requires immediate deployment-wide revocation or one global rate limit, prove that the backing architecture provides it before adding workers.

## 8. Configure audit storage and retention

Decide what evidence you need after an incident or policy review:

- where `ActionTrace` records are stored;
- retention period;
- access control for traces;
- whether the store is local, shared, append-only, backed up, or externally anchored;
- what fields are safe to retain.

Hash chaining can make mutation/reordering evident within its trust assumptions. It is not automatically non-repudiation, and deleting an unanchored local store remains possible.

Never turn audit into a secret-exfiltration path by storing raw credentials/tool results unnecessarily.

## 9. Treat redaction as defense in depth

The Context Firewall structurally bounds result size/shape and applies redaction, but built-in secret/PII detection is heuristic.

- minimize sensitive data before it reaches an agent tool when possible;
- use field/resource constraints rather than relying only on post-hoc regex redaction;
- test your domain-specific sensitive data with synthetic canaries;
- do not describe the built-in redactor as a complete DLP/data-governance system.

## 10. Pin and test protocol/integration versions

A dependency specifier is not proof of compatibility.

For every optional integration you deploy:

- use a version range that the project actually tests;
- pin/lock at the application layer according to your release practice;
- run integration tests before dependency upgrades;
- review major protocol/SDK migrations separately from routine dependency updates.

For MCP specifically, current v1 support and the v2 migration are tracked in #263/#173. Do not blindly widen the MCP major range.

## 11. Run software-supply-chain checks

At minimum:

- run `make ci` on the exact commit/release you deploy;
- review dependency-audit and CodeQL results;
- use the released package/SBOM/attestation workflow described in `RELEASE.md` where applicable;
- avoid adding optional integrations to the base runtime unless they are genuinely required.

## 12. Establish operational failure behavior

Decide how the host responds when Kernel cannot safely decide or execute:

- policy provider timeout/error;
- expired/revoked/invalid token;
- tool/driver timeout;
- malformed constraints;
- audit-store failure;
- rate-limit/budget exhaustion;
- approval broker unavailable;
- protocol incompatibility.

Security-sensitive uncertainty should normally fail closed. A fallback that widens authority requires explicit review, not an implicit exception handler.

## 13. Re-read the claims before launch

Before describing the deployment externally, compare your architecture to:

- [Security Contract](security-contract.md);
- [Security Model](security.md);
- [Roadmap](../ROADMAP.md);
- the exact released version's CHANGELOG/release notes.

If your deployment adds a stronger boundary (for example an external gateway/sandbox or shared authoritative store), document that as a property of **your deployment**, not as an unconditional Kernel guarantee.
