# Lessons Learned — Agent Context

> Canonical source for recurring mistakes and the process for capturing new lessons.
> This is not an incident archive. Only reusable, generalizable lessons belong here.

## Failure-capture workflow

When a mistake is caught in review, CI, or production:

1. **Determine if it generalizes.** Would this mistake recur if another agent or
   contributor faced a similar task? If yes, continue. If it was a one-off, stop.
2. **Write the lesson as a reusable rule.** State the mistake pattern, why it fails,
   and the correct approach. Do not write incident narrative.
3. **Assign it one canonical home:**
   - Hard invariant → [invariants.md](invariants.md)
   - Review check → [review-checklist.md](review-checklist.md)
   - Workflow rule → [workflows.md](workflows.md)
   - Recurring pattern that doesn't fit above → this file
4. **Update `AGENTS.md`** if the lesson changes a summary rule there.

## Recurring mistakes

### Docstring–implementation mismatch
**Pattern:** A docstring or PR description claims behavior that differs from the actual
code. Most frequent finding in historical code reviews.
**Why it recurs:** CI cannot detect semantic mismatches. Docstrings are written at
development time and not updated when behavior changes during implementation.
**Prevention:** Before submitting, re-read every changed docstring and verify it matches
the final implementation.

### Whitespace-only justification bypass
**Pattern:** Policy requires `justification ≥ 15 chars` for WRITE operations. A string
of 15 spaces satisfies `len()` but conveys no intent.
**Why it fails:** `len()` counts characters, not meaningful content.
**Prevention:** Validate `justification.strip()` length, not raw `len()`.

### Dead code accumulation
**Pattern:** Parameters, fixtures, or helper functions are added but never used. Linters
catch some but not all cases (e.g., unused test fixtures with `@pytest.fixture`).
**Prevention:** Search for usages of any new parameter, fixture, or helper before
submitting.

## Update triggers for this file
- A new generalizable mistake pattern is discovered.
- An existing lesson is no longer relevant (remove it).
- A lesson is promoted to a hard rule in another file (move it; don't duplicate).
