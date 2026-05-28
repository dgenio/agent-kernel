# Workflows — Agent Context

> Canonical source for workflow rules, authoritative commands, and documentation governance.
> For the review checklist, see [review-checklist.md](review-checklist.md).

## Authoritative commands

| Command | Purpose | When to run |
|---------|---------|-------------|
| `make ci` | Full pre-push gate: fmt-check → lint → type → test → example | Before every push |
| `make fmt` | Auto-format with ruff (mutates files) | During development |
| `make fmt-check` | Verify formatting with `ruff format --check` (no mutation) | Used by `make ci`; matches what CI runs |
| `make lint` | Lint check with ruff | Isolated lint verification |
| `make type` | mypy type check | After changing type annotations |
| `make test` | pytest with coverage | After changing code |
| `make example` | Run all example scripts | After changing examples or core APIs |

`make ci` is the **single authoritative pre-push command**. It runs all five targets
in sequence and matches what `.github/workflows/ci.yml` runs: the format step is the
non-mutating `fmt-check` (equivalent to CI's `ruff format --check`), and
lint/type/test/example exercise the same tools and inputs CI does. The Makefile
additionally invokes every tool via `python -m <tool>` — a local hardening over CI
that uses the active interpreter's site-packages, preventing spurious failures when
`ruff` or `mypy` are provided by isolated installers such as `uv tool` or `pipx`. If
`make ci` passes locally, the same checks will pass in CI. Use `make fmt` (the
mutating target) when you want to auto-fix formatting before re-running `make ci`.

## PR conventions

- One logical change per PR. Do not bundle unrelated changes.
- Squash-merge. Maintain a linear history.
- Conventional commit titles: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`.
- Update `CHANGELOG.md` in the same PR when adding features or fixes.
- Every new module needs a test file (`kernel.py` → `test_kernel.py`).

## Definition of done

A PR is ready for merge when:
1. `make ci` passes.
2. The review checklist in [review-checklist.md](review-checklist.md) is satisfied.
3. `CHANGELOG.md` is updated (for features and fixes).
4. No new dependencies without justification.
5. Domain vocabulary is used consistently (see `AGENTS.md`).

## Documentation governance

### When docs must be updated
- Adding a feature → update `CHANGELOG.md` + relevant docs.
- Changing a public API → update `docs/architecture.md` and any affected docs.
- Fixing a bug that contradicts documentation → fix the doc in the same PR.
- Discovering a stale doc → fix it. Code is authoritative over docs.

### How to avoid duplicate authority
- Every durable rule has exactly one canonical home (see Documentation map in `AGENTS.md`).
- Tool-specific instruction files reference `AGENTS.md` and add only tool-specific guidance.
- If you need to reference a rule from another file, use a cross-reference, not a copy.

### Update triggers for this file
- A new `make` target is added.
- PR conventions change.
- The definition of done changes.
- Documentation governance rules evolve.
