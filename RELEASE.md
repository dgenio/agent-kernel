# Release Process

This document describes how to publish a new version of `weaver-kernel` to PyPI.

## Prerequisites

- Push access to the `dgenio/agent-kernel` repository.
- Trusted Publisher configured on PyPI for this repository
  (see [Trusted Publisher setup](#trusted-publisher-setup) below).

## Steps

### 1. Bump the version

Update the `version` field in `pyproject.toml`:

```toml
[project]
version = "0.3.0"
```

### 2. Update the changelog

Add a new section to `CHANGELOG.md` under `## [Unreleased]`, then rename it
to the new version with today's date:

```markdown
## [0.3.0] - 2026-04-01

### Added
- ...

### Fixed
- ...
```

### 3. Commit and tag

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "release: v0.3.0"
git tag v0.3.0
git push origin main --tags
```

### 4. CI takes over

Pushing the `v*` tag triggers `.github/workflows/publish.yml`, which:

1. Runs the full CI suite (`make ci` equivalent) as a gate.
2. Builds the sdist and wheel with `python -m build`.
3. Publishes to PyPI using Trusted Publisher (OIDC — no API tokens stored).

Monitor the workflow run at:
<https://github.com/dgenio/agent-kernel/actions/workflows/publish.yml>

### 5. Verify

```bash
pip install weaver-kernel==0.3.0
```

## Trusted Publisher Setup

Trusted Publisher uses OpenID Connect (OIDC) so the GitHub Actions workflow can
publish to PyPI without storing API tokens as secrets.

To configure it (one-time setup):

1. Go to <https://pypi.org/manage/project/weaver-kernel/settings/publishing/>.
2. Add a new publisher:
   - **Owner**: `dgenio`
   - **Repository**: `agent-kernel`
   - **Workflow name**: `publish.yml`
   - **Environment**: `pypi`
3. Save. The `publish.yml` workflow will now authenticate automatically.

## Version scheme

This project follows [Semantic Versioning](https://semver.org/):

- **PATCH** (0.2.x): bug fixes, documentation updates.
- **MINOR** (0.x.0): new features, backward-compatible changes.
- **MAJOR** (x.0.0): breaking API changes.
