# Security Policy

Weaver Kernel sits on an agent-action enforcement boundary, so responsible vulnerability reporting is especially valuable.

## Supported versions

Security fixes are prioritized for the **latest published release** and current `main`.

| Version | Security support |
| --- | --- |
| Latest published release | Supported |
| Current `main` / unreleased next version | Fixes developed here before release |
| Older published releases | Best effort; reporters may be asked to reproduce on the latest release |

A security fix may require a fail-closed behavior change even when that is breaking. See [`docs/versioning.md`](docs/versioning.md) for the compatibility policy and [`docs/security-contract.md`](docs/security-contract.md) for the guarantees Kernel currently claims.

## Report a vulnerability privately

**Do not open a public issue for a suspected vulnerability.**

Use GitHub's private repository-security channel:

1. Open the repository's **Security** tab.
2. Choose **Advisories** / **Report a vulnerability** (wording depends on your GitHub permissions/UI).
3. Create a private draft advisory with the report.

Direct link when available:

<https://github.com/dgenio/agent-kernel/security/advisories/new>

Include, where possible:

- affected Weaver Kernel version or commit SHA;
- affected integration/deployment mode (for example MCP stdio, MCP HTTP, embedded wrapper);
- a minimal reproducer or failing test;
- the security property you expected to hold;
- whether driver/tool execution actually occurred;
- whether the issue crosses a principal, capability, constraint, output, audit, or deployment-consistency boundary;
- any suggested remediation, if you have one.

Please avoid including real credentials, secrets, customer data, or destructive production steps. A synthetic reproducer is strongly preferred.

## Response expectations

This is an open-source project, not a staffed security service and there is no contractual SLA. Maintainers nevertheless aim to:

- acknowledge a well-formed private report within **7 calendar days**;
- confirm whether the report reproduces or request additional detail;
- coordinate disclosure timing for confirmed vulnerabilities;
- credit reporters when they want attribution and disclosure is appropriate.

Complex fixes can take longer, particularly when they affect protocol compatibility or public security contracts. The maintainer will prefer an accurate fix and explicit limitation over a rushed claim that the issue is resolved.

## Security scope

High-value reports include, but are not limited to:

- a Kernel-mediated driver executing without valid authorization;
- a capability token being usable by a different principal or capability;
- signed constraints being widened or bypassed;
- malformed security configuration causing a fail-open path;
- raw/sensitive driver output bypassing the documented Context Firewall boundary;
- handle expansion escaping the original grant/principal constraints;
- audit/evidence paths leaking raw secrets or omitting an execution that the contract says must be recorded;
- protocol/integration behavior that silently weakens an advertised enforcement guarantee;
- concurrency or state-consistency behavior that violates a documented supported deployment profile.

## Important non-vulnerabilities / non-goals

Please read the [Security Contract](docs/security-contract.md) before reporting a boundary mismatch. In particular, Weaver Kernel currently does **not** claim:

- to make an LLM trustworthy;
- to prevent execution paths that bypass the in-process Kernel mediation point;
- to be a VM/container/network sandbox;
- to authenticate a `Principal` on behalf of the host;
- to provide globally consistent revocation/rate-limit/handle state across independent workers unless the deployed backing state establishes that property;
- to make heuristic PII/secret redaction a formal confidentiality proof.

A surprising result inside one of those non-goals can still be worth discussing, but it may be a product/design issue rather than a vulnerability.

## Public security issues

Once a vulnerability is fixed/disclosed, public follow-up work may be tracked in normal issues when doing so no longer exposes an unpatched weakness. Security-sensitive implementation details should stay in the private advisory until coordinated disclosure.
