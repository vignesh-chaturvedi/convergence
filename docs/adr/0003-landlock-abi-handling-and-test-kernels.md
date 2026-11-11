# ADR 0003 — Landlock ABI handling, live probes, and the kernels tests run on

**Status:** accepted · **Phase:** 1 · **Date:** 2026-11-11

## Context

Landlock grows by ABI version: 12 versions exist at kernel `v7.4-rc2`
([landlock-abi.md](../landlock-abi.md)). The kernel rejects rights it does not know, and a
kernel that does not know a right simply cannot enforce it. Convergence must never claim a
protection the running kernel lacks, and must fail closed when a policy needs one (Phase 2).

The kernels available differ widely. Observed on 2026-11-11:

- the development VM runs stock Ubuntu 24.04: 6.8.0-134, ABI 4;
- GitHub's `ubuntu-latest` is now **Ubuntu 26.04.1** (kernel 7.0.0-1019-azure, ABI 8). The
  runner annotation says the label began moving to Ubuntu 26 on 2026-10-19;
- `ubuntu-24.04-arm` runs 7.0.0-1017-azure, ABI 8.

**No GitHub-hosted runner has the stock 24.04 kernel**, which is the primary target.

## Decision

**ABI handling**

- The ABI is read from the kernel at runtime. Code never compares kernel version numbers.
- `features_for_abi(abi)` returns the cumulative rights for that ABI, capped at
  `KNOWN_MAX_ABI` (12). Rulesets are only ever built from it, so unknown bits never reach the
  kernel.
- The ruleset attribute is passed at the shortest size that covers the fields in use, so
  older kernels see only fields they know.
- Errata are queried and reported for information only, as the kernel documentation advises.

**Proof, not version numbers**

- Every protection `doctor` reports as `verified` has a live probe. The probe applies the
  feature in a throwaway forked child, then checks a positive control and a denial, and
  where possible an external effect (no file created, no connection received).
- A protection whose ABI is present but has no live probe yet (`RESOLVE_UNIX`, UDP ports,
  namespace/capability permissions) is reported as `abi-only`, never as `verified`.
- A probe that fails on a kernel claiming support is reported as `failed` and treated as
  missing.
- The minimum enforcement set is filesystem Landlock (any ABI), a seccomp filter,
  `no_new_privs`, and resource limits. `doctor` exits 1 without it.

**Test kernels**

- Local development uses the stock 24.04 kernel (ABI 4) in a Lima VM.
- CI runs the tests on `ubuntu-latest`, `ubuntu-24.04`, and `ubuntu-24.04-arm` (cloud
  kernels with ABI 8, covering the scope probes that ABI 4 cannot run).
- CI also boots the pinned Ubuntu 24.04 cloud image (the same Lima template, x86_64) in a
  nested QEMU/KVM VM and runs the tests there, so the ABI 4 path is tested in CI too.
- The separate HWE-kernel VM planned earlier is dropped: the CI kernels already provide a
  newer ABI, and the 8 GB development host runs only one VM comfortably.

## Consequences

- The same live tests assert ABI-dependent expectations computed from the kernel's own
  answer. They pass on ABI 4 and on ABI 8, and exercise different probes on each.
- Features added in ABIs 9–12 have no live kernel available yet (the newest seen is ABI 8).
  Their table entries are checked against the kernel documentation by unit tests, but the
  features themselves are untested on a real kernel, and `doctor` reports them as
  `abi-only`. ABI 5 and 6 features are probed live on the CI kernels.
- If the nested-VM CI job cannot run (no KVM on the runner), ABI 4 evidence comes from the
  local VM only, and the README must say that.
