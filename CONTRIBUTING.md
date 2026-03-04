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
make fmt    # auto-format with ruff
make lint   # lint with ruff
make type   # type-check with mypy
make test   # run pytest with coverage
make ci     # all of the above + examples
```

## Pull request guidelines

1. Keep PRs focused — one logical change per PR.
2. Add or update tests for every behaviour change.
3. All checks in `make ci` must pass.
4. Follow the existing code style (ruff-enforced).
5. Write docstrings on all public interfaces.

## Security

Please report security vulnerabilities privately via GitHub Security Advisories.
Do **not** open a public issue for a security bug.
