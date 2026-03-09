# Claude Instructions — agent-kernel

Read `AGENTS.md` before making any changes. It is the canonical source of truth
for all shared rules, conventions, and documentation pointers.

## Explore before acting

- Read `AGENTS.md` and the relevant `docs/agent-context/` file for the topic
  before proposing changes.
- Check existing code patterns in the target area. Do not infer repo-wide
  conventions from a single file.
- When path-specific conventions exist (see Code conventions in `AGENTS.md`),
  follow them exactly.

## Implement safely

- Preserve invariants. Consult `docs/agent-context/invariants.md` before any
  change that touches security, tokens, policy, or the firewall.
- Use only the conventions documented in `AGENTS.md`. Do not invent new ones.
- Use `make ci` as the single validation command. Do not guess alternatives.
- Do not "clean up" or "simplify" code unless the change was requested. Hidden
  constraints may exist.

## Validate before completing

- Run `make ci` and confirm it passes.
- If a public API, workflow, invariant, or convention changed, update the
  relevant canonical doc in the same changeset.
- Verify that every changed docstring matches the final implementation.
- Check for dead code: unused parameters, fixtures, or helpers.

## Handle contradictions

When docs contradict code or each other:
1. Code is authoritative over docs.
2. Canonical shared docs (`AGENTS.md`, `docs/agent-context/`) are authoritative
   over tool-specific files.
3. Surface the contradiction explicitly. Do not silently pick one side.
4. Fix stale docs in the same changeset when possible.

## Capture lessons

When a mistake or unexpected pattern is discovered during work:
1. Determine if it generalizes — would it recur in a similar task?
2. If yes, identify the canonical home using the workflow in
   `docs/agent-context/lessons-learned.md`.
3. Treat candidate lessons as provisional. Do not promote a fresh observation
   into durable guidance from a single incident.

## Update order

1. Update canonical shared docs (`AGENTS.md`, `docs/agent-context/`) first.
2. Update tool-specific files (this file, `.github/copilot-instructions.md`)
   second.
3. If a Claude-specific rule becomes shared and durable, promote it into
   canonical docs and remove it from `.claude/`.
