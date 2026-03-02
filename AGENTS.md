# AGENTS.md — AI Agent Instructions

This file provides instructions for AI coding agents (Copilot, Cursor, etc.) working in this repository.

## Repo layout

```
src/agent_kernel/   — library source (one module per concern, ≤300 lines each)
tests/              — pytest test suite
examples/           — runnable demos (no internet required)
docs/               — architecture and security documentation
```

## Quality bar

- `make ci` must pass before every commit.
- All public interfaces need type hints and docstrings.
- Use custom exceptions from `errors.py` — never bare `ValueError` or `KeyError`.
- Keep modules ≤ 300 lines. Split if needed.
- No randomness in matching, routing, or summarization (deterministic outputs).

## Security rules

- Never log or print secret key material.
- HMAC secrets come from `AGENT_KERNEL_SECRET` env var; fall back to a random dev secret with a logged warning.
- Tokens are tamper-evident (HMAC-SHA256) but not encrypted — document this.
- Confused-deputy prevention: tokens bind to `principal_id + capability_id + constraints`.

## Adding a new capability driver

1. Implement the `Driver` protocol in `src/agent_kernel/drivers/`.
2. Register it with `StaticRouter` or implement a custom `Router`.
3. Add integration tests in `tests/test_drivers.py`.

## Adding a new policy rule

1. Add the rule to `DefaultPolicyEngine.evaluate()` in `policy.py`.
2. Cover it with a test in `tests/test_policy.py`.
