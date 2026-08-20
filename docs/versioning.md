# Versioning, stability and deprecation policy

Weaver Kernel uses Semantic Versioning as a communication framework, with an explicit **pre-1.0 stability policy** because the library is still refining its security and integration contracts.

The goal is not to promise that `0.x` never changes. The goal is to make every supported change predictable enough that downstream teams can decide when and how to upgrade.

## What is the public API?

The supported Python API is the surface intentionally exported through `weaver_kernel.__all__`, plus documented public submodules that are explicitly described as supported.

The repository pins the top-level export contract in `tests/test_public_api.py` and the public docstring contract in `tests/test_docstrings.py`.

The following are **not** stable API unless separately documented:

- names beginning with `_`;
- implementation modules reached through deep imports only;
- test fixtures/internal helpers;
- example-only code;
- experimental APIs whose docs explicitly say they may change;
- serialized/wire formats that do not have a published versioned schema or conformance contract.

A downstream import working today does not by itself make that import public API.

## Semantic-version interpretation before 1.0

### Patch release: `0.x.y → 0.x.(y+1)`

Patch releases should be compatible bug fixes, security fixes, documentation corrections and implementation changes that preserve the supported public contract.

A security fix may deliberately make previously permissive or undefined behavior fail closed. If that affects a supported usage pattern, the release notes must call it out prominently even when the public Python signature is unchanged.

### Minor release: `0.x.y → 0.(x+1).0`

Minor releases may add features and may contain **deliberate breaking changes** while the project is pre-1.0, but breaking changes are not license for surprise churn.

A planned breaking change must have:

1. a written rationale tied to security, correctness, interoperability or a validated product need;
2. a migration path where technically possible;
3. a CHANGELOG/release-note entry identifying the break;
4. compatibility/deprecation handling when keeping the old behavior temporarily does not weaken security;
5. tests that pin the intended new contract.

Minor releases should not bundle unrelated breaking changes merely because “0.x allows it.”

### Major release: `0.x.y → 1.0.0`

`1.0.0` means the project is prepared to treat its documented supported surfaces as a long-lived compatibility contract. It does **not** mean that every experimental idea in the backlog is complete.

## Deprecation mechanics

When an old API can remain safely available:

1. introduce the replacement;
2. keep the old name/behavior as an alias or compatibility path;
3. document the replacement in the CHANGELOG and migration notes;
4. emit `DeprecationWarning` where doing so is reliable and useful;
5. keep the compatibility path for at least **two minor releases** unless a security or correctness issue requires faster removal;
6. remove it in a later minor release before 1.0, or in a major release after 1.0.

The `agent_kernel` → `weaver_kernel` naming transition and compatibility-alias work are the model: migrate deliberately rather than carrying ambiguous names forever or deleting them without warning.

## When we may skip a deprecation window

A deprecation window is not required when preserving the old behavior would itself be unsafe or misleading.

Examples:

- a fail-open security default;
- accepting malformed signed security configuration;
- silently granting authority from missing metadata;
- behavior that violates a documented invariant;
- compatibility with a protocol version that cannot be implemented correctly without weakening validation.

In these cases the project should prefer a **fail-closed breaking fix**, but must still provide:

- prominent release notes;
- explicit migration instructions where possible;
- regression tests;
- a documented compatibility opt-back only when the opt-back is itself safe enough to offer deliberately.

Security should not be weakened to preserve accidental compatibility.

## Stable reason codes and machine contracts

Machine-consumed reason codes, exported schemas and versioned evidence/token contracts deserve stricter treatment than prose error messages.

When a reason code is documented as stable:

- do not repurpose it to mean a different condition;
- add a new code for a new condition;
- keep adapters/tests branching on the code rather than parsing human-readable messages.

When a wire artifact becomes cross-language or independently implemented, it must have an explicit schema/version and conformance fixtures before it is described as stable.

## Integration compatibility

Framework/protocol support is versioned as part of the product contract.

For an advertised integration, documentation should state:

- dependency/SDK versions tested in CI;
- which execution surfaces are actually mediated;
- known unsupported/bypass surfaces;
- whether support is stable, provisional or experimental.

A dependency range in `pyproject.toml` should reflect what CI proves, not what dependency resolution happens to accept.

Major dependency transitions such as MCP SDK v1 → v2 therefore require explicit migration/interoperability work rather than a blind version-range widening.

## Security-contract changes

[`security-contract.md`](security-contract.md) is a compatibility surface too.

A release that narrows or broadens a security claim must update:

- the contract;
- executable invariant/security tests;
- affected integration coverage matrices;
- release notes.

Broadening a claim requires evidence. Narrowing a claim because implementation reality was previously overstated is considered a correctness fix and should happen immediately.

## Criteria for 1.0

The project can consider `1.0.0` when all of the following are true:

- [ ] the security contract has remained coherent across multiple releases and maps to executable tests;
- [ ] no known fail-open issue remains on the advertised supported paths;
- [ ] identity/principal provenance and deployment-consistency assumptions are documented for production profiles;
- [ ] supported framework/protocol version envelopes are continuously tested;
- [ ] the public API definition is mechanically pinned and the deprecation policy has been followed in practice for at least two minor releases;
- [ ] externally reviewed threat-model findings have been incorporated into the supported contract;
- [ ] the project has genuine independent downstream use, not only maintainer-authored demos;
- [ ] any implementation-neutral Weaver contracts claimed as stable have conformance fixtures and at least one independent consumer/implementation where the claim depends on interoperability;
- [ ] release/package/docs drift is controlled so a released user sees the behavior the current documentation promises.

These are readiness criteria, not a date commitment.

## Change checklist for contributors

Before changing a public or security-sensitive surface, ask:

1. Is this public API, a machine contract, a security contract, or an internal detail?
2. Does the change break a documented supported behavior?
3. Can a compatibility path exist without weakening security/correctness?
4. What exact migration does a downstream adopter need?
5. Which tests make the old/new contract visible?
6. Does the CHANGELOG/release note need a `Changed`, `Deprecated`, `Removed` or security note?
7. Does an integration compatibility matrix or `security-contract.md` need to change?

If the answers are unclear, treat the change as potentially breaking until reviewed.
