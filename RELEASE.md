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

## Writing release notes

The `publish.yml` workflow seeds the GitHub Release with **auto-generated notes**
(a flat list of merged PR titles). Those are a starting point, not the finished
product — **rewrite them** before the release is done.

Release notes are a **decision-support document**, not a commit log. Optimize for
the reader making a decision, not the maintainer looking up a PR. Write for these
readers, in priority order:

1. **Existing adopters** deciding *"do I upgrade, and will it break me?"* — lead
   with breaking changes and migrations.
2. **Security auditors and AI agents** deciding *"is this safe to adopt/bump?"* —
   call out security-relevant and behavior-default changes explicitly, so they
   can be found without reading prose.
3. **Evaluators** deciding *"is this project alive and going my way?"* — give a
   short narrative of the release's theme.
4. **Maintainers / future self** — keep PR links as trailing citations.

Structure (mirror `CHANGELOG.md`; do not invent a third format):

- **Highlights** — 2–3 sentences naming the release's theme.
- **⚠️ Breaking changes** *first* — exact symbol + migration for each.
- **🔒 Security** — fail-closed/default changes, redaction, supply-chain; tagged.
- **✨ New features** — grouped by theme, flagship first.
- **🔧 Infrastructure & docs** — collapse Dependabot/CI churn into a line or two;
  never let it dominate the notes.
- **🤖 For automated tooling** — an explicit, greppable list of new public
  symbols plus a pointer to the breaking-change section.
- **Full Changelog** compare link last.

Apply the rewrite to the live release with a notes file (avoids shell-escaping):

```bash
gh release edit v<version> --notes-file <notes.md>
```

Non-negotiables for this library:

- **Breaking-changes-first** and **security-tagged** — fail-closed behavior is
  the whole value proposition, so upgrade-safety information leads.
- Keep the notes **consistent with `CHANGELOG.md`**; the two surfaces must not
  drift.
- **Bury dependency-bump noise**; surface behavior and API changes.

Revisit this convention if the audience mix changes — a stable 1.x with many
production adopters would weight migrations even more heavily, while a
pre-adoption phase weights the evaluator narrative. Update this section when the
logic should change.

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
