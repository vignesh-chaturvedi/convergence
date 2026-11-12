# Releasing

Releases are published by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
when a `v*` tag is pushed. It uses PyPI **trusted publishing**: GitHub proves to PyPI which
workflow is running, so no API token exists anywhere.

## One-time setup (the project owner)

These steps need the owner's PyPI account; nobody else can do them.

1. **PyPI.** Go to <https://pypi.org/manage/account/publishing/> and add a *pending
   publisher*:
   - PyPI project name: `convergence-sandbox`
   - Owner: `vignesh-chaturvedi`
   - Repository name: `convergence`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. **Recommended:** in the GitHub repository settings, under *Environments → pypi*, add
   yourself as a required reviewer. Then nothing reaches PyPI until you approve it, even
   after the tag is pushed.

## Each release

1. Set `version` in `pyproject.toml`, and move the `[Unreleased]` entries of
   `CHANGELOG.md` under the new version.
2. Run `scripts/vm.sh check`, and make sure CI is green on `main`.
3. Tag and push: `git tag -a v0.1.0 -m "Convergence 0.1.0" && git push origin v0.1.0`.

The workflow then:
1. checks that the tag matches the version, builds the sdist and wheel, and runs
   `twine check --strict`;
2. publishes to **PyPI**, after your approval if the `pypi` environment requires it;
3. installs the published package from PyPI on a fresh `ubuntu-24.04` runner and runs
   `convergence doctor`.

There is no TestPyPI step. The first attempt of 0.1.0 used one; TestPyPI refused it, because
no trusted publisher there matched, so it was dropped at the owner's choice. Nothing had been
published at that point.

Before the first release, the wheel was also installed on a fresh Ubuntu 24.04 VM (stock
kernel 6.8, aarch64), where `doctor`, a sandboxed run, and `convergence mcp` were checked.
