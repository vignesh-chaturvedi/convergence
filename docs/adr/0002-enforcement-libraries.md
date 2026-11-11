# ADR 0002 — Own ctypes Landlock binding, libseccomp for seccomp filters

**Status:** accepted · **Phase:** 1 · **Date:** 2026-11-11

## Context

Convergence needs three things from the kernel: Landlock (filesystem, TCP ports, scopes),
seccomp-bpf (syscall filtering with integer-argument checks), and
`PR_SET_NO_NEW_PRIVS`. The project is Python only (ADR 0001). It should build on maintained
libraries rather than reimplement primitives, and it must run on the stock Ubuntu 24.04
kernel: 6.8, Landlock ABI 4, verified in the development VM.

Checked on 2026-11-11:

| Option | Facts |
|---|---|
| **sandlock** (multikernel/sandlock v0.9.1, Apache-2.0) | Rust core with a Python ctypes SDK; manylinux wheels for x86_64 and aarch64. `MIN_ABI = 6` is a hard floor (`crates/sandlock-core/src/protection.rs`), so it **does not run on ABI 4**. IP allowlisting, `/proc` virtualisation, copy-on-write, and memory/process limits run through a seccomp user-notification supervisor; `no_supervisor` mode keeps the ABI 6 floor. Also ships `sandlock learn` and an MCP server, which are prior art for this project. |
| **`landlock`** on PyPI (Edward-Knight/landlock, MIT) | Only `1.0.0.devN` pre-releases; last upload May 2025. Filesystem rights only: no ABI 4 network rules, no scopes. |
| **libseccomp's official Python bindings** | Cython; shipped by distributions (`python3-seccomp`) but not on PyPI, so a `pip install` cannot depend on them. |
| **`pyseccomp`** (ctypes over libseccomp) | Last release 2021. |
| **libseccomp** itself | 2.5.5 is installed by default on Ubuntu 24.04 (systemd depends on it) and is present on the GitHub runners. Stable C API. |
| **Hand-written classic BPF** | No dependency, but architecture checks (x32 and 32-bit compat syscalls on x86_64) and syscall numbering would be ours to get right. |

## Decision

- **Landlock:** a small ctypes binding over the three system calls
  (`src/convergence/kernel/landlock.py`). Constants and layouts are taken from the kernel's
  UAPI header ([landlock-abi.md](../landlock-abi.md)). Packed structures are encoded with
  `struct` so there is no ctypes packing ambiguity.
- **seccomp:** ctypes over libseccomp's stable, non-variadic API
  (`src/convergence/kernel/seccomp.py`), loaded as `libseccomp.so.2`. Filters are compiled by
  libseccomp in the supervising process and exported as classic BPF. The child installs the
  finished program with a single `prctl(PR_SET_SECCOMP)`, so no library code runs between
  fork and exec. Only the native architecture is added to a filter, and the bad-architecture
  action kills the process.
- **seccomp user notification is not used** at all in Phase 1, and is never used as an
  enforcement boundary.
- sandlock is cited as prior art, not used as a dependency.

## Consequences

- Convergence works on the stock 24.04 kernel (ABI 4), which sandlock does not.
- About 400 lines of binding code are ours to maintain. They are covered by unit tests
  for encodings and the ABI table, and by live kernel tests that use every binding for real
  (`tests/test_kernel_live.py`, and the `doctor` probes).
- libseccomp becomes a runtime requirement. It is present on stock Ubuntu, and `doctor`
  reports clearly when it is missing; the minimum enforcement set then fails.
- New Landlock ABIs need a code change, which is deliberate: `KNOWN_MAX_ABI` caps what is
  used, `doctor` warns when the kernel is newer, and the ABI table is test-checked against
  the kernel documentation.
