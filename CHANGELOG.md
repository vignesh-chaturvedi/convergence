# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it is released.

## [Unreleased]

### Added

- Phase plan (`PLAN.md`) with the verified development environment and exit gates.
- Project skeleton: `convergence-sandbox` distribution (src layout, `uv_build`), the
  `convergence` command with `--version`, and `python -m convergence`. The CLI states that
  no enforcement is implemented yet.
- Tooling: ruff (lint and format), mypy in strict mode, pytest with `kernel`, `escape`,
  `holdout`, and `slow` markers, and a locked dependency set (`uv.lock`).
- `scripts/vm.sh`: creates and drives an Ubuntu 24.04 Lima VM on macOS, and runs the same
  commands directly on Linux. `scripts/provision.sh` installs uv 0.13.6, verified against
  SHA-256 checksums pinned in the script.
- `scripts/kernel-facts.sh`: prints kernel facts that matter for sandboxing (kernel, LSMs,
  Landlock ABI, seccomp state, strace, libseccomp, and the Yama and user-namespace sysctls).
  It is informational and is not the capability probe.
- GitHub Actions CI: lint, format, and type check, plus tests on `ubuntu-latest` (x86_64)
  and `ubuntu-24.04-arm` (arm64) for Python 3.12 and 3.13. Actions are pinned by commit
  SHA, and each test job prints the runner's kernel facts.
- ADR template and ADR 0001 (Python on kernel primitives, tested on real kernels).
