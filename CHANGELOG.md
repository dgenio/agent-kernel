# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-29

### Added
- Capability namespaces and hierarchical discovery in `CapabilityRegistry`:
  dot-notation `capability_id`s now expose `list_namespaces()` /
  `list_namespace(prefix)` operations; `register_namespace(prefix, loader=...)`
  enables deferred registration for large tool ecosystems (the loader runs
  at most once on first access). `search()` gained an `offset` kwarg for
  pagination, strips a small stop-word set, and now scores with a
  BM25-flavoured ranker that weights `capability_id`/`tags` matches above
  `description`. Flat (un-namespaced) capability IDs continue to work
  unchanged. (#45)
- Capability marketplace, part 1 — manifest format & local registry: new
  `CapabilityDescriptor` and `CapabilityManifest` dataclasses (both
  JSON-round-trippable via `to_dict`/`from_dict`), new
  `agent_kernel.federation` module with `build_manifest()`,
  `import_manifest()`, and `merge_sensitivity()`, and new `Kernel.advertise()`
  / `Kernel.import_remote()` methods. `Kernel` gained a `kernel_id`
  argument used as the manifest publisher identity. Three trust policies
  are honoured at import time (`most_restrictive` (default), `local_only`,
  `remote_deferred`); imported capabilities are routed through a
  caller-supplied driver and flow through the full local policy → token →
  firewall pipeline. HMAC tokens remain kernel-scoped — a token issued by
  one kernel cannot be verified by another with a different secret. New
  errors `NamespaceNotFound`, `FederationError`, `ManifestError`,
  `TrustPolicyError`. (#52)
- New docs: [`docs/federation.md`](docs/federation.md) for the marketplace
  protocol and a namespace section in
  [`docs/capabilities.md`](docs/capabilities.md).
- Capability marketplace, part 2 — federated discovery: new
  `agent_kernel.federation_discovery` module with `discover_peers()`,
  `sign_manifest()`, `verify_manifest()`, `serve_manifest_payload()`, and
  `DiscoveryRateLimiter`. `Kernel.discover_peers()` fetches one or more
  manifests over HTTP from peer URLs or a registry URL. Signed envelopes
  (HMAC-SHA256) detect tampering and let importers refuse unsigned
  manifests when a verification secret is in play (and vice versa). New
  errors `ManifestSignatureError` and `DiscoveryError`. (#51, closes #49)
- OpenTelemetry integration: new `agent_kernel.otel` module with
  `instrument_kernel(kernel)` that wraps `Kernel.invoke` and
  `Kernel.grant_capability` with OTel spans + metrics (invocation count,
  latency histogram, denial counter). No-op when the optional `[otel]`
  extra is not installed (`OTEL_AVAILABLE` reports the runtime status).
  Idempotent — repeat calls on the same kernel are no-ops. (#38)
- Streaming firewall: new `Firewall.apply_stream()` async-iterator method
  that processes driver chunks one-at-a-time, applying PII redaction
  per-chunk. New `StreamingDriver` Protocol in `drivers/base.py` extends
  `Driver` with an optional `execute_stream()`. New `Kernel.invoke_stream()`
  yields `Frame` chunks; the last chunk carries `is_final=True`. Drivers
  without `execute_stream` automatically fall back to a single-chunk stream
  via `execute()`. `Frame` gained an `is_final: bool` field. (#47)
- `examples/readme_quickstart.py` — a runnable mirror of the README quickstart,
  wired into `make example` and the CI "Examples" step. Together with
  `tests/test_readme_quickstart.py` (which extracts and runs the inline README
  snippet itself), CI fails if the documented quickstart stops producing the
  expected output. (#83)

### Changed
- Tech debt: `policy_dsl.py` decomposed (was 661 lines). Parsing and
  schema dataclasses now live in `policy_dsl_parser.py`
  (`PolicyMatch`, `PolicyRule`, `parse_engine_data`, `parse_rule`,
  YAML/TOML loaders), and the denial-explanation traversal in
  `policy_dsl_explain.py`. The public import surface
  (`DeclarativePolicyEngine`, `PolicyMatch`, `PolicyRule`) is unchanged.
  `RateLimiter` and rate-limit constants extracted from `policy.py` into
  a new `rate_limit.py` module; `policy.py` continues to re-export them
  under their original names. (#68)
- Tech debt: `kernel.py` split into the `agent_kernel.kernel` sub-package
  to honour AGENTS.md's ≤ 300-line module bar. The `Kernel` class lives
  in `kernel/__init__.py`; heavy methods (invoke pipeline, dry-run,
  federation, streaming) delegate to sibling modules. Existing
  `from agent_kernel import Kernel` / `from agent_kernel.kernel import Kernel`
  imports are unchanged. (#68)

### Documentation
- Fixed handle-expansion examples that omitted the now-required `principal`
  argument and therefore raised `HandleConstraintViolation` when copy-pasted:
  the README quickstart (#83) and `docs/context_firewall.md` +
  `docs/architecture.md` (#84) now pass `principal=` and link to
  `docs/security.md#handle-expansion-boundary`. The README quickstart also
  drops two unused imports (`ExecutionContext`, `HMACTokenProvider`).
- `docs/capabilities.md` "Sensitivity tags" now lists `SensitivityTag.MEMORY`
  and links to `docs/security.md#memory-actions`. (#89)
- Corrected the base-dependency list in `docs/agent-context/invariants.md` and
  `docs/agent-context/architecture.md` from "`httpx` only" to
  "`httpx` + `pydantic`", pointing to `AGENTS.md` as the canonical dependency
  policy. (#90)
- The `agent_kernel` module docstring's `Errors::` block now lists every
  exported error class — added `TokenRevoked`, `AdapterParseError`,
  `CapabilityAlreadyRegistered`, `HandleConstraintViolation`,
  `ManifestSignatureError`, and `DiscoveryError`. (#91)

### Tests
- Added explicit dry-run regression tests for `HTTPDriver` and `MCPDriver`,
  pinning the kernel's driver-agnostic dry-run short-circuit. (#68)
- `tests/test_public_api.py` — asserts every error class exported via `__all__`
  appears in the `agent_kernel` module docstring, preventing public-API
  docstring drift. (#91)
- `tests/test_readme_quickstart.py` — extracts the README quickstart code block
  and executes it, asserting the documented output so the inline snippet cannot
  silently drift from the working API. (#83)

### Fixed
- `merge_sensitivity()` (and `most_restrictive` imports) now ranks the `MEMORY`
  sensitivity tag instead of silently treating it as `NONE`. (#52)
- `import_manifest()` is now atomic: a manifest whose capability ID is already
  registered locally — or that lists the same ID more than once — raises
  `ManifestError` and registers nothing, instead of leaving a partial,
  unrouted import behind. (#52)
- `CapabilityRegistry.search()` now triggers every pending deferred namespace
  loader before ranking, so matches are no longer missed when the query shares
  no token with a namespace prefix. (#45)
- A deferred namespace loader that fails (by raising or returning an
  out-of-namespace capability) no longer permanently disables the namespace —
  the load is retried on a later access. (#45)
- `Makefile` now invokes every tool via `python -m <tool>` (matching the
  existing `test` target) so `make ci` uses the active interpreter's
  site-packages instead of whatever `ruff` / `mypy` resolves first on
  `PATH`. Fixes spurious `import-not-found` / `no-redef` errors on machines
  where `mypy` or `ruff` is provided by an isolated installer such as
  `uv tool` or `pipx`. (#86)
- `make ci` now runs the non-mutating `fmt-check` target (`ruff format
  --check`) instead of the file-mutating `fmt` target. Local `make ci`
  now fails on unformatted code exactly like `.github/workflows/ci.yml`
  does, instead of silently auto-fixing the working tree and letting an
  unfixed commit be pushed. `make fmt` remains available for manual
  auto-formatting. `AGENTS.md`, `docs/agent-context/workflows.md`,
  `docs/agent-context/review-checklist.md`, `CONTRIBUTING.md`, and the
  `README.md` development section are updated to describe the new chain. (#88)

## [0.8.0] - 2026-05-22

### Added
- "Secure your first MCP tool in 5 minutes" tutorial: new
  [`docs/tutorial.md`](docs/tutorial.md) walks a new reader from install to a
  working invocation, covering registration, principals, grants, the three
  LLM-safe response modes (`summary` / `table` / `handle_only`), handle
  expansion, policy denial with stable `reason_code`, and `explain()`
  audit. The admin-only `raw` mode is described but not exercised by the
  walkthrough. Companion runnable example
  [`examples/tutorial.py`](examples/tutorial.py) uses `InMemoryDriver`
  (offline, zero external deps) and is exercised by `make example` and CI;
  it now `assert`s that no PII field leaks into the LLM-safe Frame so a
  firewall regression fails the build. (#46)
- README "How this relates to neighboring projects" section: a neutral
  boundaries table covering `AgentFence` (external CLI/proxy gate),
  `contextweaver` (context compilation library), `ChainWeaver`
  (deterministic flow orchestrator), and `weaver-spec` (specification +
  conformance suite), plus a "When *not* to use this" callout. (#71)
- Grant-constraint enforcement on handle expansion (#76). `Handle` now carries
  the `principal_id` and `constraints` from the original grant, persisted at
  handle creation time by `HandleStore.store`. `HandleStore.expand` rechecks
  these against the requested expand query:
  - A request `limit` larger than the grant's `max_rows` is rejected with
    `HandleConstraintViolation` (`reason_code = handle_constraint_violation`).
  - A request `fields` entry outside `allowed_fields` is rejected; an
    unscoped expand applies `allowed_fields` as the default projection.
  - A request filter that disagrees with the grant's `scope` is rejected;
    the scope filter is otherwise AND-merged so the caller cannot bypass it.
  - A `principal_id` parameter that does not match the handle's stored
    principal raises `HandleConstraintViolation`
    (`reason_code = handle_principal_mismatch`).
- `SensitivityTag.MEMORY` and memory-action policy rules in
  `DefaultPolicyEngine` (#75). Project-scoped memory reads are allowed by
  default; sensitive-scoped reads require the `memory_reader_sensitive` role
  (or `admin`); writes always require `memory_writer` (or `admin`). The
  `explain()` path lists the same conditions with stable `reason_code`s.
- New stable `DenialReason` codes: `HANDLE_CONSTRAINT_VIOLATION`,
  `HANDLE_PRINCIPAL_MISMATCH`, `MEMORY_WRITE_REQUIRES_WRITER`,
  `MEMORY_SENSITIVE_READ_DENIED`.
- `HandleConstraintViolation` error class (subclass of `AgentKernelError`,
  exported from `agent_kernel`) — carries an optional `reason_code` matching
  the `DenialReason` vocabulary so handle-side and grant-side denials share
  one set of stable codes.
- `Kernel.expand` accepts an optional `principal: Principal` argument that
  is forwarded to `HandleStore.expand` for principal-mismatch checks.
- Memory-action input redaction (#75): `ActionTrace.args` for any capability
  whose ID starts with `memory.` has payload-like keys (`payload`, `content`,
  `value`, `memory`, `text`, `body`) replaced with `"[REDACTED]"`. Keys are
  preserved so audit can confirm the action took place without exposing the
  durable content the agent wrote or read.
- New `tests/test_firewall_boundary.py` (#74) — focused regression suite that
  pushes synthetic secret/PII values through the raw → `Frame` boundary
  end-to-end and asserts those values never appear in summary/table/raw
  frames, are stripped by `allowed_fields`, never reach `ActionTrace.args`
  for memory capabilities, and stay quarantined when raw mode is downgraded
  for non-admin principals.

### Security
- Closes #76: handle expansion can no longer return data outside the original
  grant's `max_rows` / `allowed_fields` / `scope`, and handle IDs are no
  longer bearer credentials that work across principals.
- Closes #75: memory reads and writes are governed actions with stable
  denial codes and trace-side redaction of durable payloads.
- Closes #74: redaction boundary is pinned by negative assertions against
  fake-secret strings, catching future regressions that drop a redaction
  step or route raw data through a new path.

## [0.7.0] - 2026-05-20

### Added
- Structured intent and scope metadata on `CapabilityRequest`: new optional
  `intent: str | None` and `scope: dict[str, Any]` fields let policy engines
  authorize based on machine-readable intent and scope alongside the existing
  free-text `goal`. `DeclarativePolicyEngine` rules can match on these via new
  `intent: [...]` and `scope: {key: value}` clauses in YAML/TOML policy files.
  Intent-aware allow rules fail closed for legacy callers that don't set an
  intent. (#72)
- Structured policy decision trace (`PolicyDecisionTrace` + `PolicyTraceStep`):
  both built-in policy engines now attach a step-by-step trace to every
  `PolicyDecision` (allow and deny paths). Each step records the rule
  considered, the outcome (`matched`/`skipped`/`denied`/`allowed`/
  `constraint_applied`), a human-readable detail, and — for terminal
  steps — the stable reason code. Traces echo `intent` and `scope_keys`
  (scope dimension names only — values redacted) from the request and contain
  no raw argument values. `DryRunResult.policy_decision`
  also carries a synthesized single-step trace. (#73)
- Stable machine-readable denial reason codes: new `DenialReason` and
  `AllowReason` enums in `agent_kernel.policy_reasons` (also exported as
  `from agent_kernel import DenialReason, AllowReason`). Every built-in
  denial path on `DefaultPolicyEngine` and `DeclarativePolicyEngine` populates
  `PolicyDecision.reason_code`, `DenialExplanation.reason_code`,
  `FailedCondition.reason_code`, and `PolicyDenied.reason_code`. Tests should
  assert on these codes instead of matching the human-readable `reason` /
  `narrative` strings, which remain part of the API but may evolve for
  clarity. Codes: `missing_role`, `missing_tenant_attribute`,
  `missing_attribute`, `insufficient_justification`, `invalid_constraint`,
  `rate_limited`, `no_matching_rule`, `explicit_deny_rule`,
  `intent_not_allowed`, `scope_not_allowed`; allow-side: `default_policy_allow`,
  `rule_allow`, `default_fallthrough_allow`. (#77)
- New public exports: `AllowReason`, `DenialReason`, `PolicyDecisionTrace`,
  `PolicyTraceStep`.

### Changed
- `PolicyDecision` gained optional `reason_code: str | None` and
  `trace: PolicyDecisionTrace | None` fields (both default `None` so
  third-party engines that don't populate them keep working).
- `DenialExplanation` and `FailedCondition` gained optional `reason_code`
  fields populated by both built-in engines on every denial path.
- `PolicyDenied(reason_code=...)` keyword argument: the exception now carries
  a `reason_code` attribute so callers can branch on a stable code without
  matching the human-readable message.

## [0.6.0] - 2026-05-19

### Added
- Cross-invocation context budget manager (`BudgetManager`) tracks cumulative token usage across
  multiple `Kernel.invoke()` calls within a session. When attached to a `Kernel` via the new
  `budget_manager` keyword argument, the kernel reserves a budget slice before each invocation
  and reconciles actual frame-payload usage afterwards. As the remaining budget shrinks the
  requested `response_mode` is auto-escalated to a more aggressive tier (> 50% remaining keeps
  the caller's mode; 20–50% downgrades `raw` to `table`; 5–20% floors at `summary`; < 5% forces
  `handle_only`). `Kernel.invoke(..., dry_run=True)` now also reports `budget_remaining` and the
  escalated `response_mode` when a manager is configured. The `BudgetManager` is optional and
  off by default — existing kernels are unchanged. (#44)
- `TokenCounter` protocol and `default_token_counter` (character-based `len(json.dumps(...))//4`
  approximation) provide pluggable token counting without runtime dependencies. A new optional
  `[tiktoken]` extra is reserved for callers that want to plug in `tiktoken`-based counting.
- `BudgetExhausted(AgentKernelError)` raised by `BudgetManager.allocate()` (and by
  `Kernel.invoke()` before driver execution) when the cumulative session budget is fully spent.
- `BudgetConfigError(AgentKernelError)` raised by `BudgetManager` for invalid configuration or
  validation failures (non-positive budgets, negative allocate/record/release amounts), replacing
  bare `ValueError` so callers can catch budget mistakes via the `AgentKernelError` hierarchy
  per `AGENTS.md` ("never raise bare ValueError to callers").
- New public exports: `BudgetManager`, `BudgetExhausted`, `BudgetConfigError`, `TokenCounter`,
  `default_token_counter`, and `Kernel.budget` accessor property.
- LLM tool-format adapters and middleware (`agent_kernel.adapters`): `OpenAIMiddleware` (OpenAI
  Responses API + Chat Completions, auto-detected on input) and `AnthropicMiddleware` (Anthropic
  Messages with `cache_control` support). Both translate `Capability` objects to vendor tool
  schemas, route tool calls through the full kernel pipeline (grant → invoke → firewall → trace),
  and surface kernel errors (`PolicyDenied`, `CapabilityNotFound`, `DriverError`) as tool-result
  errors so the LLM can react. Pre/post hooks (`intercept_tool_call`, `intercept_tool_result`,
  sync or async) support logging, metrics, approval gates, and per-call justification injection.
  Zero runtime dependency on the `openai` / `anthropic` SDK packages. (#55, #50, #40)
- New `Capability` fields for LLM adapters: `parameters_model: type[pydantic.BaseModel] | None`
  (input schema source + validation), `parameters_schema: dict | None` (raw JSON Schema escape
  hatch), and `tool_hints: ToolHints | None` (vendor hints — Anthropic `cache_control`, OpenAI
  `strict` mode). All default to ``None``; existing capabilities and tests are unaffected.
- New `ToolHints` dataclass and `OpenAIMiddleware` / `AnthropicMiddleware` top-level exports.
- New `AdapterParseError(AgentKernelError)` exception raised by adapter parse / validation
  helpers (`tool_call_to_request`, `tool_use_to_request`, `make_namespace_safe_name`) instead
  of bare `ValueError`. Satisfies `AGENTS.md`'s "no bare ValueError to callers" rule and
  gives consumers a stable adapter-specific exception type. Also catches capability IDs that
  contain the reserved OpenAI namespace separator `__` (which would otherwise produce
  colliding tool names).
- `Kernel.list_capabilities()` convenience accessor returning every registered capability in
  registration order. Used by the new adapters but generally useful for tooling that needs to
  enumerate the registry without keyword search.
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
- Runtime dependencies now include `pydantic>=2` in addition to `httpx`. Pydantic is used by the new
  `agent_kernel.adapters` package for JSON-Schema generation and argument validation when a
  `Capability` declares a `parameters_model`. Existing kernel behavior is unchanged; pydantic is not
  imported at module load by anything outside the adapters.
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

### Documentation
- `docs/architecture.md` now describes `PolicyEngine` / `ExplainingPolicyEngine` protocols,
  `DefaultPolicyEngine` and `DeclarativePolicyEngine` (with policy-DSL semantics), and dry-run
  mode (admin gate, operation resolution rule). Closes the canonical "Components & API
  reference" gap flagged in audit.
- `docs/capabilities.md` adds a "Dry-run mode" section (semantics, the three parity rules,
  no-side-effects guarantee), a "Declarative policies" section (loaders, match conditions,
  optional-extra behaviour), and a "Denial explanations" section. Closes the affected-files
  gap from issue #43.

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
- `drivers/mcp.py` adds an explicit `_McpError: type[BaseException] | None` annotation so mypy
  `--strict` remains happy across the try/except import branches.

### Tests
- `tests/test_policy.py` adds `test_declarative_replicates_default_policy_decisions` — a
  comparative test asserting that `DeclarativePolicyEngine` and `DefaultPolicyEngine` produce
  the same allow/deny outcomes across a curated scenario matrix (READ × non-sensitive / PII /
  PCI / SECRETS, WRITE/DESTRUCTIVE with and without required roles and justification). Closes
  issue #42's "comparative test" acceptance criterion.

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
