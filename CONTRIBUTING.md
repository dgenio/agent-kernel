# Contributing to agent-kernel

Thank you for your interest in contributing!

## Development setup

```bash
git clone https://github.com/dgenio/agent-kernel.git
cd agent-kernel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks

```bash
make fmt        # auto-format with ruff (not run by `make ci`)
make fmt-check  # verify formatting with `ruff format --check` (no mutation)
make lint       # lint with ruff
make type       # type-check with mypy
make test       # run pytest with branch coverage (fails under the coverage floor)
make ci         # fmt-check + lint + type + test + example
```

`.github/workflows/ci.yml` invokes these same Makefile targets, so a green
`make ci` locally means a green CI run — the two cannot drift.

## Quality gates enforced by `make test`

These run as ordinary pytest checks (no extra commands):

- **Coverage floor (ratchet).** `[tool.coverage.report] fail_under` in
  `pyproject.toml` is the enforced minimum branch coverage. The rule is a
  **ratchet: only ever raise it, never lower it.** If a change pushes coverage
  comfortably above the floor, bump `fail_under` up to lock the gain in.
- **Docstring gate** (`tests/test_docstrings.py`). Every symbol exported from
  `weaver_kernel.__all__` must have a Google-style docstring; functions that
  take parameters must include an `Args:` section. Type aliases and constants
  are exempt. Highest-traffic helpers also carry runnable doctests
  (`tests/test_doctests.py`).
- **Architecture conformance** (`tests/test_architecture.py`). Import
  boundaries (`firewall`/`drivers`/`router`/`models` stay within their allowed
  leaf imports) and the 300-line module budget are enforced; over-budget files
  are pinned with a shrink-only ceiling. See AGENTS.md → "Architectural
  conformance".

## Pull request guidelines

1. Keep PRs focused — one logical change per PR.
2. Add or update tests for every behaviour change.
3. All checks in `make ci` must pass.
4. Follow the existing code style (ruff-enforced).
5. Write docstrings on all public interfaces.

## Security

Please report security vulnerabilities privately via GitHub Security Advisories.
Do **not** open a public issue for a security bug.
