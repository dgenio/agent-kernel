# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Declarative policy engine (`DeclarativePolicyEngine`) that loads rules from YAML or TOML files.
  Rules are evaluated top-down with first-match-wins semantics; supports `safety_class`, `sensitivity`,
  `roles`, `attributes`, and `min_justification` match conditions. (#42)
- Policy denial explanation: `ExplainingPolicyEngine` protocol plus `DefaultPolicyEngine.explain()` and
  `DeclarativePolicyEngine.explain()` implementations return a structured `DenialExplanation` with a
  `FailedCondition` list for every failing check (no short-circuit), a `remediation` list, and a
  human-readable `narrative`. (#48)
- Dry-run invocation mode: `kernel.invoke(..., dry_run=True)` verifies the token and resolves the
  execution plan without calling the driver. Returns `DryRunResult` with the resolved `driver_id`,
  `operation`, `response_mode`, and an `estimated_cost` tier (`low`/`medium`/`high`). (#43)
- `Kernel.explain_denial()` convenience method that calls the policy engine's `explain()` for a given
  `CapabilityRequest` and `Principal` without requiring a token. Raises `AgentKernelError` when the
  configured engine does not implement `explain()`.
- New public types exported from `agent_kernel`: `DeclarativePolicyEngine`, `ExplainingPolicyEngine`,
  `PolicyEngine`, `PolicyMatch`, `PolicyRule`, `DenialExplanation`, `FailedCondition`, `DryRunResult`,
  `PolicyConfigError`.
- `policy` optional extra (`pip install weaver-kernel[policy]`) pulls in `pyyaml` and `tomli` (Python 3.10).
- Example policy files in `examples/policies/` (YAML and TOML formats).

### Changed
- `PolicyEngine` protocol no longer requires `explain()`. Engines that need to support
  `Kernel.explain_denial()` should implement the new `ExplainingPolicyEngine` protocol. Built-in
  engines satisfy both. This avoids a breaking typing change for downstream implementers.
- `DeclarativePolicyEngine` now defers `yaml` and `tomllib`/`tomli` imports into the corresponding
  loaders, so `import agent_kernel` works without the `policy` extra installed. Calling
  `from_yaml`/`from_toml` without the parser surfaces a `PolicyConfigError` with an install hint.
- `Kernel.invoke(dry_run=True)` resolves `operation` the same way drivers do
  (`args.get("operation", capability_id)`) so `DryRunResult.operation` matches what a driver would
  actually receive — instead of `capability.impl.operation`, which can diverge.
- `Kernel.invoke(dry_run=True)` mirrors the Firewall's admin-only gate for `raw` mode: non-admin
  principals see their requested `raw` mode downgraded to `summary` in `DryRunResult`, matching
  what they would actually get at real-invoke time. Prevents probing for raw availability.

### Fixed
- `DeclarativePolicyEngine._parse_rule()` now validates the types of `roles`, `attributes`,
  `min_justification`, and `constraints` in policy files and raises `PolicyConfigError` with a
  precise message instead of silently producing misbehaving rules or raising at evaluation time.
- `DeclarativePolicyEngine.explain()` now correctly reports explicit deny rules that fully match
  (previously fell through to the misleading `no_matching_rule` fallback and dropped the rule's
  reason). Partial-match deny rules are now skipped so the explanation focuses on actionable allow
  rules instead of suggesting changes that would only trigger the deny.
- Example policy files (`examples/policies/default.{yaml,toml}`) now use the correct `default` key
  (was `default_action`, which the parser silently ignored), express PII-with-tenant as an allow
  rule paired with default-deny (the previous deny rule was inverted under first-match-wins), and
  order the `allow-secrets-service` rule before the deny rule (the deny was previously unreachable).
- `Kernel.explain_denial()` docstring no longer contradicts itself ("never raises" vs.
  `CapabilityNotFound`).
- `DryRunResult.budget_remaining` docstring no longer references the unimplemented `BudgetManager`;
  the field is documented as reserved for a future cross-invocation budget mechanism.
- `drivers/mcp.py` adds an explicit `_McpError: type[Exception] | None` annotation so mypy `--strict`
  remains happy across the try/except import branches.

## [0.5.0] - 2026-04-12

### Added
- Built-in `MCPDriver` with stdio and Streamable HTTP transports, tool auto-discovery, normalized MCP result handling, and optional dependency guardrails.
- Declared weaver-spec v0.1.0 compatibility in README: invariants I-01 (firewall), I-02 (authorization + audit), and I-06 (scoped tokens) are satisfied.
- Added placeholder `conformance_stub` CI job that will activate once the weaver-spec conformance suite ships (dgenio/weaver-spec#4).

## [0.4.0] - 2026-03-14

### Added
- Sliding-window rate limiting in `DefaultPolicyEngine` per `(principal_id, capability_id)` pair (#39).
  Default limits by safety class: 60 READ / 10 WRITE / 2 DESTRUCTIVE per 60s window.
  Service-role principals get 10× limits. Configurable via constructor.
- GitHub Release step in publish workflow — creates a release with auto-generated notes and artifacts before publishing to PyPI.

### Fixed
- `HTTPDriver`: DELETE requests now forward args as query params instead of silently dropping them.

### Removed
- Dead `_truncate_str` helper in `firewall/transform.py` (defined but never called).

## [0.3.0] - 2026-03-09

### Added
- Structured logging at kernel decision points (invoke, grant, deny, revoke).
- Agent-facing documentation system: `docs/agent-context/` (architecture, workflows, invariants, lessons-learned, review-checklist).
- `.github/copilot-instructions.md` — review-critical projections for GitHub Copilot.
- `.claude/CLAUDE.md` — Claude-specific operating instructions.
- PyPI publish workflow (`.github/workflows/publish.yml`) with Trusted Publisher (OIDC) (#37).
- `RELEASE.md` documenting the full release process.
- `[project.urls]` in `pyproject.toml` (Homepage, Repository, Documentation, Changelog).
- Optional dependency groups: `mcp` and `otel` in `pyproject.toml`.

### Changed
- Rewrote `AGENTS.md` with full domain vocabulary, security rules, code conventions, documentation map, and weaver-spec references.
- Renamed PyPI package from `agent-kernel` to `weaver-kernel` to align with Weaver ecosystem.
- Added `workflow_call` trigger to CI workflow so publish workflow can reuse it as a gate.

### Refactored
- Extracted `_log_verify_failure` helper in `tokens.py`.
- Consolidated invoke logging with shared base dict in `kernel.py`.
- Extracted `_deny` static method in policy engine.

### Fixed
- Pinned GitHub Actions to commit SHAs in publish workflow.
- Added `contents:read` permission to publish job.
- Clarified PyPI vs import name in README Quickstart.

## [0.2.0] - 2026-03-06

### Added
- Token revocation support: `revoke_token()` and `revoke_all()` on `Kernel` (#33, #57).
- `SECRETS` sensitivity tag enforcement in policy engine and redaction (#56).

### Fixed
- Policy engine now strips whitespace from justification before length check.
- Policy engine reports both raw and stripped length in justification errors.
- Policy engine checks role before justification in all safety/sensitivity blocks.
- Redaction preserves field-name context in API key and connection string patterns.
- `revoke_all()` drops `_principal_tokens` entry after revoking.

## [0.1.0] - 2024-01-01

### Added
- Initial scaffold: `CapabilityRegistry`, `PolicyEngine`, `HMACTokenProvider`, `Kernel`.
- `InMemoryDriver` and `HTTPDriver` (httpx-based).
- Context `Firewall` with `Budgets`, redaction, and summarization.
- `HandleStore` with TTL, pagination, field selection, and basic filtering.
- `TraceStore` and `explain()` for full audit trail.
- Examples: `basic_cli.py`, `billing_demo.py`, `http_driver_demo.py`.
- Documentation: architecture, security model, integrations, capabilities, context firewall.
- CI pipeline for Python 3.10, 3.11, 3.12 with ruff + mypy + pytest.
