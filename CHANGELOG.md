# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it is released.

## [Unreleased]

### Added

- `convergence doctor` (text and `--json`, schema `convergence.doctor/1`): reports the
  kernel, LSMs, Landlock ABI and errata, libseccomp, strace, and the calling process's
  privileges and seccomp state. It proves each feature with a live probe in a throwaway
  forked child, using a positive control, a denial, and where possible an external check.
  Probed live: Landlock filesystem rights, `REFER`, `TRUNCATE`, TCP ports, `IOCTL_DEV`,
  signal and abstract-unix scoping; seccomp argument filtering; `no_new_privs`;
  `RLIMIT_FSIZE`; ptrace through strace. Landlock features with no live probe yet (ABI 9-12)
  are reported as `abi-only`, never as verified. Exits 1 if the minimum enforcement set
  (filesystem Landlock, seccomp, `no_new_privs`, rlimits) is unavailable. The calling
  process is never confined.
- ctypes bindings: Landlock (`kernel/landlock.py`: ABI and errata queries, rulesets, path
  and port rules, `restrict_self`, a per-ABI feature table for ABI 1-12) and libseccomp
  (`kernel/seccomp.py`: build a filter, export classic BPF, install it with `prctl`).
- `docs/landlock-abi.md`: what each Landlock ABI adds, the structure layouts, and the errata,
  sourced from kernel `v7.4-rc2`. ADR 0002 (enforcement libraries) and ADR 0003 (ABI
  handling and test kernels).
- `docs/evidence/doctor/`: `doctor` output from the Ubuntu 24.04 GA-kernel VM (ABI 4).
- Tests: the ABI table, structure encodings, and protection logic for every ABI level;
  live kernel tests for the bindings, the forked-child runner, and `doctor` end to end.
- CI: an explicit `ubuntu-24.04` x86_64 job, `doctor` reports uploaded as artifacts, and a
  job that boots the stock Ubuntu 24.04 kernel in a nested QEMU/KVM VM through Lima.
  `scripts/vm.sh` can drive a VM on Linux (`CONVERGENCE_USE_VM=1`) and no longer downloads
  containerd for new VMs.
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
