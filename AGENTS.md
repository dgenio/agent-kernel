# AGENTS.md — AI Agent Instructions

This is the canonical source of truth for AI coding agents working in this repository.
Tool-specific instruction files (`.github/copilot-instructions.md`, `.claude/CLAUDE.md`)
reference this file and add only tool-specific guidance.

## Repo layout

```
src/agent_kernel/        — library source (one module per concern, ≤300 lines each)
  drivers/               — capability drivers (one file per driver)
  firewall/              — context firewall (redaction, summarization, budgets)
tests/                   — pytest suite (one test file per module)
examples/                — runnable demos (prefer offline; network OK with fallback)
docs/                    — reference documentation
docs/agent-context/      — deeper agent guidance (architecture, workflows, invariants)
```

## Weaver ecosystem

agent-kernel is part of the **Weaver ecosystem**:
- [weaver-spec](https://github.com/dgenio/weaver-spec) — formal specification with invariants
- [contextweaver](https://github.com/dgenio/contextweaver) — context compilation library
- ChainWeaver — orchestration layer

This repo must conform to weaver-spec invariants. Key invariants (all equally critical):
- **I-01**: Every tool output must pass through a context boundary before reaching the LLM.
- **I-02**: Context boundaries must enforce budgets (size, depth, field count).
- **I-06**: Tokens must bind principal + capability + constraints; no reuse across principals.

Full spec: [dgenio/weaver-spec](https://github.com/dgenio/weaver-spec)

## Domain vocabulary

Use these terms consistently. Never substitute synonyms:

| Term | Means | Not |
|------|-------|-----|
| capability | a registered, auditable action | tool, function, API |
| principal | the identity invoking a capability | agent, user, caller |
| grant | a policy-approved token issuance | permission, access |
| Frame | the bounded, redacted result returned to the LLM | response, output |

## Quality bar

- `make ci` must pass before every push. It runs: `fmt → lint → type → test → example`.
- All public interfaces need type hints and docstrings.
- Never raise bare `ValueError` or `KeyError` to callers. Use custom exceptions from `errors.py`. Catching stdlib exceptions internally to remap them is fine.
- Error messages are part of the contract — tests must assert both exception type and message.
- Keep modules ≤ 300 lines. Split if needed.
- No randomness in matching, routing, or summarization. Deterministic outputs always.
- No new dependencies without justification. The dep list is intentionally minimal (`httpx` only).

## Security rules

- Never log or print secret key material.
- HMAC secrets come from `AGENT_KERNEL_SECRET` env var; fallback to a random dev secret with a logged warning.
- Tokens are HMAC-signed but **not encrypted**. Never store secrets in token payloads.
- Confused-deputy prevention: tokens bind `principal_id + capability_id + constraints`.
- Never bypass token verification before capability invocation.
- Firewall always transforms `RawResult → Frame`. Raw driver output never reaches the LLM.
- Non-admin principals never get `raw` response mode. The Firewall downgrades to `summary`.
- No duplicate capability IDs in the registry.

See [docs/agent-context/invariants.md](docs/agent-context/invariants.md) for the full "never do" list and security traps.

## Code conventions

**All modules (`src/agent_kernel/`):**
Relative imports. Dataclasses with `slots=True`. Protocols for interfaces.
`__all__` in every `__init__.py`. Google-style docstrings.
`CamelCase` for classes, `snake_case` for functions. Error classes end with `Error`.

**Drivers (`drivers/`):**
One file per driver. `Driver` Protocol in `base.py`. Async `execute()` method.
Driver classes end with `Driver`. Use `DriverError` for exceptions.

**Firewall (`firewall/`):**
Pure functions for redaction and summarization. `Firewall` class in `transform.py` orchestrates.
Use `FirewallError` for exceptions.

**Tests (`tests/`):**
Every module has a corresponding test file (`kernel.py` → `test_kernel.py`).
Conftest fixtures only for cross-test reuse (≥2 test files). Local helpers otherwise.

**Examples (`examples/`):**
Prefer offline. Network examples OK only with a clear fallback.

## Workflow

- One logical change per PR. Squash-merge. Conventional commit titles (`feat:`, `fix:`, `test:`, `docs:`).
- `make ci` is the single authoritative pre-push command.
- Update `CHANGELOG.md` in the same PR when adding features or fixes.
- Code is authoritative over docs. Fix stale docs when you spot discrepancies.

See [docs/agent-context/workflows.md](docs/agent-context/workflows.md) for full details.

## Adding a capability driver

1. Implement the `Driver` protocol in `src/agent_kernel/drivers/`.
2. Register it with `StaticRouter` or implement a custom `Router`.
3. Add integration tests in `tests/test_drivers.py`.

See [docs/integrations.md](docs/integrations.md) for MCP and HTTP examples.

## Adding a policy rule

1. Add the rule to `DefaultPolicyEngine.evaluate()` in `policy.py`.
2. **Placement matters:** rules are evaluated in order. A new rule placed before sensitivity checks silently bypasses them.
3. If adding a new `SensitivityTag`, you must also add a corresponding policy rule — otherwise the tag is silently ignored.
4. Cover it with a test in `tests/test_policy.py`.

## Review checklist (beyond `make ci`)

Before submitting a PR, verify:
- [ ] Docstrings and descriptions match the actual implementation.
- [ ] Security edge cases handled (whitespace-only justification, truncated JSON, bare `int()` on untrusted input).
- [ ] No dead or unused code (parameters, fixtures, helpers).
- [ ] No backward compatibility breaks (e.g., adding required methods to a Protocol).
- [ ] Naming consistent across docs and code (use capability, principal, grant, Frame — never synonyms).

See [docs/agent-context/review-checklist.md](docs/agent-context/review-checklist.md) for the full checklist.

## Documentation map

| Topic | Canonical source |
|-------|-----------------|
| Architecture & design intent | [docs/agent-context/architecture.md](docs/agent-context/architecture.md) |
| Components & API reference | [docs/architecture.md](docs/architecture.md) |
| Security model & threats | [docs/security.md](docs/security.md) |
| Hard invariants & forbidden shortcuts | [docs/agent-context/invariants.md](docs/agent-context/invariants.md) |
| Workflow rules & commands | [docs/agent-context/workflows.md](docs/agent-context/workflows.md) |
| Recurring mistakes | [docs/agent-context/lessons-learned.md](docs/agent-context/lessons-learned.md) |
| Review & self-check | [docs/agent-context/review-checklist.md](docs/agent-context/review-checklist.md) |
| Driver integration patterns | [docs/integrations.md](docs/integrations.md) |
| Capability design conventions | [docs/capabilities.md](docs/capabilities.md) |
| Context firewall details | [docs/context_firewall.md](docs/context_firewall.md) |

## Update policy

Code is authoritative. When docs contradict code, fix the docs.
Each topic has one canonical source (see table above). Update the canonical source;
do not create parallel guidance elsewhere.
