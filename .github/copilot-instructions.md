# Copilot Instructions — agent-kernel

> Canonical rules: `AGENTS.md`. This file projects review-critical rules that
> must be visible during GitHub PR review.

## Review checklist

Flag these in every PR — CI does not catch them:

- Docstrings and descriptions must match actual implementation.
- No security bypass vectors: whitespace-only justification, truncated JSON, bare `int()` on untrusted input.
- No dead code: unused parameters, fixtures, or helpers.
- No backward-compat breaks: adding required methods to an existing Protocol breaks downstream.
- Naming consistent: use capability, principal, grant, Frame — never synonyms.

Canonical checklist: `docs/agent-context/review-checklist.md`

## Code and docs reviewed together

- PRs that change public APIs, workflows, invariants, review rules, or path conventions must include doc updates.
- If a docstring changed, verify it matches the final code.
- Code is authoritative over docs. Fix stale docs in the same PR.
- Surface contradictions explicitly. Do not silently work around them.

## Invariants

Non-negotiable. Violations silently degrade security:

- Firewall always mediates: `RawResult → Frame`. Never bypass.
- Token verification before every invocation. Never skip.
- Non-admin principals never get `raw` response mode.
- Policy rule ordering is security-critical — a rule placed before sensitivity checks creates a silent bypass.
- New `SensitivityTag` values need a matching policy rule, or the tag is silently ignored.

Full list: `docs/agent-context/invariants.md`

## Convention discipline

- Follow conventions in `AGENTS.md`. Do not invent new ones.
- `make ci` is the single pre-push command. Do not guess alternatives.
- Custom exceptions from `errors.py` only. Never raise bare `ValueError`/`KeyError` to callers (catching stdlib internally to remap is fine).
- No new dependencies without justification.

## Canonical sources

| Topic | File |
|-------|------|
| All shared rules | `AGENTS.md` |
| Hard invariants | `docs/agent-context/invariants.md` |
| Full review checklist | `docs/agent-context/review-checklist.md` |
| Workflows & commands | `docs/agent-context/workflows.md` |
| Recurring mistakes | `docs/agent-context/lessons-learned.md` |
| Architecture intent | `docs/agent-context/architecture.md` |
