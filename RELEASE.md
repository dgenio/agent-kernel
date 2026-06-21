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
version = "0.4.0"
```

### 2. Update the changelog

Add a new section to `CHANGELOG.md` under `## [Unreleased]`, then rename it
to the new version with today's date:

```markdown
## [0.4.0] - 2026-03-14

### Added
- ...

### Fixed
- ...
```

### 3. Commit and tag

> **Important:** Tag only on `main` after the release commit is merged.
> The publish workflow triggers on any `v*` tag push — tagging a non-main
> commit would publish unreleased code.

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "release: v0.4.0"
git tag v0.4.0
git push origin main --tags
```

### 4. CI takes over

Pushing the `v*` tag triggers `.github/workflows/publish.yml`, which:

1. Runs the full CI suite (`make ci` equivalent) as a gate.
2. Builds the sdist and wheel with `python -m build`.
3. Generates a CycloneDX SBOM of the published runtime tree (`weaver-kernel.cdx.json`).
4. Creates a GitHub Release with auto-generated notes, the built artifacts, and the SBOM attached.
5. Publishes to PyPI using Trusted Publisher (OIDC — no API tokens stored) with
   PEP 740 attestations generated and uploaded automatically.

Monitor the workflow run at:
<https://github.com/dgenio/agent-kernel/actions/workflows/publish.yml>

### 5. Verify

```bash
pip install "weaver-kernel==<version>"
```

### Supply-chain artifacts (SBOM + attestations)

Each release ships verifiable provenance:

- **SBOM** — a CycloneDX 1.6 JSON describing the published package's runtime
  dependency tree, attached to the GitHub Release as `weaver-kernel.cdx.json`.
  It is generated from a clean install of the built wheel, so it reflects what
  adopters actually receive (not the build environment).
- **PyPI attestations** — PEP 740 digital attestations signed via the Trusted
  Publisher OIDC identity, shown under "Provenance" on the
  [PyPI project page](https://pypi.org/project/weaver-kernel/).

Consumers can verify the attestations with the
[`pypi-attestations`](https://pypi.org/project/pypi-attestations/) CLI:

```bash
pip download --no-deps "weaver-kernel==<version>"
python -m pypi_attestations verify pypi \
  --repository https://github.com/dgenio/agent-kernel \
  weaver_kernel-<version>-py3-none-any.whl
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
