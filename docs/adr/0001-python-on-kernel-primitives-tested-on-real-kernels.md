# ADR 0001 — Python on kernel primitives, tested only on real kernels

**Status:** accepted · **Phase:** 0 · **Date:** 2026-11-11

## Context

Convergence enforces least-privilege policies with Linux kernel features: Landlock,
seccomp-bpf, `PR_SET_NO_NEW_PRIVS`, and resource limits. The project's claims are only as
good as the environment its tests run in. Two constraints shape the choice:

- The project is Python (3.12+). Its value is the policy layer, generating policies from
  observations, the MCP interface, and the measurements. Its value is not new bindings to
  kernel primitives.
- The development machine is macOS on Apple silicon, where none of these primitives exist.

Docker Desktop runs Linux in a VM whose kernel is chosen by Docker. Containers start with a
default seccomp profile, and often without the ability to create namespaces. A sandbox
tested there can look like it works when a primitive was blocked by the outer container, or
look broken when the container blocked a probe. Divergence hit this directly: Docker denied
network-namespace creation during its sandbox verification (Divergence ADR 0011).

Checked on 2026-11-11, in a Lima 2.2.0 VM (vz, Ubuntu 24.04.4 LTS cloud image):

| Fact | Value |
|---|---|
| Kernel | `6.8.0-134-generic` aarch64 (the 24.04 GA kernel) |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor` |
| Landlock ABI | 4 |
| seccomp | available; the login shell is not filtered (`Seccomp: 0`) |
| libseccomp / strace | 2.5.5 / 6.8, both preinstalled |

## Options considered

- **Docker Desktop**: already installed, but rejected for the reasons above.
- **A Lima VM with the stock Ubuntu 24.04 cloud image**: a real, unmodified distribution
  kernel, the one a "fresh Ubuntu 24.04 machine" gets. The repo is shared over virtiofs at
  the same path, so commands and paths are identical on both sides.
- **OrbStack or UTM**: viable, but not installed. Lima was already present and is scriptable
  with a single CLI.

## Decision

- Convergence is written in Python 3.12+ and calls kernel interfaces directly or through
  maintained C libraries. The project contains no Rust code. Which libraries are used is
  decided in ADR 0002 (Phase 1).
- All code runs and all tests run on real Linux kernels: a Lima VM with the stock Ubuntu
  24.04 kernel for local development (`scripts/vm.sh`), and GitHub Actions `ubuntu-latest`
  (x86_64) and `ubuntu-24.04-arm` (arm64) in CI. Linux contributors run the same scripts
  directly on their host.
- Docker Desktop is never used as evidence for enforcement behaviour. Security tests never
  mock the kernel.
- The virtualenv lives on the Linux side's own disk (`$HOME/.venvs/convergence`), not on the
  shared mount.

## Consequences

- Every enforcement claim can be reproduced with `scripts/vm.sh create`, `provision`, and
  `check`, or directly on any Ubuntu 24.04 machine.
- The primary target is the GA kernel with Landlock ABI 4. Features that need a newer ABI
  are exercised on a second VM with the HWE kernel (Phase 1), and are reported as not
  enforced where the running kernel lacks them.
- The CI kernels are a separate environment. Their Landlock and seccomp support is checked
  in Phase 1 before any CI job is trusted for enforcement results. Each test job already
  prints the runner's kernel facts.
- The local VM is arm64 and CI covers both arm64 and x86_64. Architecture-specific
  behaviour, such as seccomp's x32 and 32-bit compat handling on x86_64, is only verified
  on the CI runner.
