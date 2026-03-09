# Review Checklist — Agent Context

> Canonical source for pre-submit self-checks and review gates.
> Use this for both agent self-check and maintainer review.
> For hard invariants, see [invariants.md](invariants.md).
> For workflow rules, see [workflows.md](workflows.md).

## Pre-submit self-check

Run before every PR submission.

### CI gate
- [ ] `make ci` passes (fmt → lint → type → test → example).

### Correctness
- [ ] Every changed docstring matches the actual implementation.
- [ ] Error messages are tested — tests assert both exception type and message string.
- [ ] Every new module has a corresponding test file.
- [ ] Every new `SensitivityTag` has a matching policy rule in `evaluate()`.

### Security
- [ ] No secret key material in logs, error messages, or traces.
- [ ] No security edge-case bypass vectors: whitespace-only justification, truncated
      JSON passed to `json.loads()`, bare `int()` on untrusted input.
- [ ] Token verification is not skipped or short-circuited.
- [ ] Firewall step is not bypassed — `RawResult → Frame` remains mandatory.
- [ ] No new `raw` response mode paths for non-admin principals.

### Backward compatibility
- [ ] No new required methods added to an existing Protocol (breaks downstream).
- [ ] If a Protocol must change, consider a separate Protocol or default implementations.

### Code hygiene
- [ ] No dead or unused code: parameters, fixtures, helpers.
- [ ] Modules stay ≤ 300 lines.
- [ ] Custom exceptions from `errors.py`, not bare `ValueError`/`KeyError` to callers.
- [ ] Domain vocabulary used consistently: capability, principal, grant, Frame.

### Documentation
- [ ] `CHANGELOG.md` updated (for features and fixes).
- [ ] Naming consistent across docs and code (no mixed terminology).
- [ ] Stale docs fixed if spotted (code is authoritative).

## Cross-file consistency checks

When a change touches one of these areas, verify the related files stay aligned:

| If you change... | Also check... |
|------------------|---------------|
| A Kernel public method | `docs/architecture.md`, `AGENTS.md`, README quickstart |
| Policy rules or `SensitivityTag` | `docs/capabilities.md`, `AGENTS.md` security rules |
| Firewall behavior | `docs/context_firewall.md`, `AGENTS.md` security rules |
| Driver Protocol | `docs/integrations.md`, `AGENTS.md` driver how-to |
| `pyproject.toml` version | `src/agent_kernel/__init__.py` `__version__` |
| Dependency list | `AGENTS.md` (justification required) |
| Error classes | `errors.py` naming convention (must end with `Error`) |
| Review checklist items | `.github/copilot-instructions.md` review checklist |

## Update triggers for this file
- A new review pattern is identified from PR feedback.
- A lesson from [lessons-learned.md](lessons-learned.md) is promoted to a review check.
- CI gains new checks that make a manual check redundant (remove it).
- The definition of done changes (sync with [workflows.md](workflows.md)).
