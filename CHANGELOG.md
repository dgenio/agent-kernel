# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
