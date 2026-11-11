# Landlock ABI versions and what Convergence does with them

Landlock is versioned by an **ABI number**, not by kernel version. A program asks the running
kernel for its ABI with `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
and may only use the rights that ABI defines: the kernel rejects unknown bits with `EINVAL`.
Convergence detects the ABI at runtime and never hard-codes kernel version numbers.

## Sources

Everything below comes from the Linux kernel tree at commit `067c5c24cef2`
(2026-11-10, `v7.4-rc2`):

- `include/uapi/linux/landlock.h`: constants, structures, and per-right ABI notes;
- `Documentation/userspace-api/landlock.rst`: the compatibility switch and the
  "Previous limitations" section, one entry per ABI;
- `security/landlock/fs.c`: `ACCESS_FILE`, the rights that apply to regular files;
- `security/landlock/errata/abi-*.h`: the errata.

The only kernel version these sources tie to an ABI is that Landlock first appeared in
Linux 5.13 (ABI 1). Convergence relies on the ABI number alone.

## What each ABI adds

| ABI | Adds | Kind | Convergence today |
|---:|---|---|---|
| 1 | `EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`, `MAKE_CHAR`, `MAKE_DIR`, `MAKE_REG`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK`, `MAKE_SYM` | filesystem rights | live-probed by `doctor` (`landlock.fs`) |
| 2 | `REFER`: rename and link across directories. Before ABI 2, Landlock refuses every cross-directory rename or link with `EXDEV` | filesystem right | live-probed by `doctor` (`landlock.refer`) |
| 3 | `TRUNCATE`. Before ABI 3, truncation cannot be denied | filesystem right | live-probed by `doctor` (`landlock.truncate`) |
| 4 | `NET_BIND_TCP`, `NET_CONNECT_TCP` by port | network rights | live-probed by `doctor` (`landlock.net_tcp`) |
| 5 | `IOCTL_DEV`: ioctl on character and block devices | filesystem right | live-probed by `doctor` (`landlock.ioctl_dev`) |
| 6 | `SCOPE_ABSTRACT_UNIX_SOCKET`, `SCOPE_SIGNAL` | scopes | live-probed by `doctor` (`landlock.scope_*`) |
| 7 | audit-logging flags for `landlock_restrict_self` | flags | no: audit records need privileges to read |
| 8 | `RESTRICT_SELF_TSYNC`: enforce on every thread | flag | no: Convergence restricts a single-threaded child before exec |
| 9 | `RESOLVE_UNIX`: connections to pathname unix sockets | filesystem right | reported from the ABI only; no live probe yet |
| 10 | `NET_BIND_UDP`, `NET_CONNECT_SEND_UDP` by port; quiet rule flag | network rights | reported from the ABI only; no live probe yet |
| 11 | `RESTRICT_SELF_NO_NEW_PRIVS` flag | flag | no: `prctl(PR_SET_NO_NEW_PRIVS)` works on every ABI |
| 12 | `PERMISSION_NAMESPACE_USE`, `PERMISSION_CAPABILITY_USE` | permissions | reported from the ABI only; no live probe yet |

Convergence does not enforce policies yet (that is Phase 4); today only `doctor` uses these
rights, to prove what the kernel supports. A kernel newer than ABI 12 is used as ABI 12. `doctor` warns that the newer features are
unused.

"Reported from the ABI only" means `convergence doctor` shows the status `abi-only`. The
kernel says it has the feature, but this version of Convergence has not proven it with a
live test, and no test kernel has offered it yet (the newest seen is ABI 8). Such features
are never reported as verified.

## Structures

| Structure | Layout | Notes |
|---|---|---|
| `landlock_ruleset_attr` | seven `__u64`: `handled_access_fs`, `handled_access_net`, `scoped`, `quiet_access_fs`, `quiet_access_net`, `quiet_scoped`, `handled_permissions` | Older kernels know only a prefix. Convergence passes the shortest size that covers the fields it sets: 8, 16, 24, or 56 bytes. |
| `landlock_path_beneath_attr` | `__u64 allowed_access; __s32 parent_fd;` | **packed**: 12 bytes, no padding |
| `landlock_net_port_attr` | `__u64 allowed_access; __u64 port;` | 16 bytes |

Rights that may be granted on a **regular file** rather than a directory (`ACCESS_FILE`):
`EXECUTE`, `WRITE_FILE`, `READ_FILE`, `TRUNCATE`, `IOCTL_DEV`, `RESOLVE_UNIX`.

System call numbers are the same on x86_64 and arm64: `landlock_create_ruleset` 444,
`landlock_add_rule` 445, `landlock_restrict_self` 446.

## Errata

`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ERRATA)` returns a bitmask of
fixed errata. Kernels without the query reject the flag with `EINVAL`. The kernel
documentation advises against changing behaviour based on errata, so `doctor` reports them
for information only.

| Erratum | Applies to | Issue |
|---:|---:|---|
| 1 | ABI 4 | Non-TCP stream sockets (SMC, MPTCP, SCTP) were wrongly restricted by the TCP rights |
| 2 | ABI 6 | Signal scoping blocked signals between threads of the same process in different domains |
| 3 | ABI 1 | Disconnected directories (a directory moved outside a bind mount) could widen rights through rename or link, bypassing `REFER` |
| 4 | ABI 1 | Creating OverlayFS whiteouts required `MAKE_CHAR`; it now requires `MAKE_REG` |

## Kernels tested

Each row is a `convergence doctor --json` report produced on that kernel. Those reports are
the evidence; this table summarises them.

| Environment | Kernel | ABI | Live probes | Errata fixed / applicable but not fixed | Evidence |
|---|---|---:|---|---|---|
| Lima VM, Ubuntu 24.04.4 stock GA kernel, aarch64 | 6.8.0-134-generic | 4 | 8 verified; `ioctl_dev` and both scopes unavailable (need ABI 5 and 6) | 1 / 3, 4 | [lima-ubuntu-24.04-ga-aarch64](evidence/doctor/lima-ubuntu-24.04-ga-aarch64.json) |
| CI nested QEMU/KVM VM, Ubuntu 24.04.4 stock GA kernel, x86_64 | 6.8.0-134-generic | 4 | same as above | 1 / 3, 4 | [ci-ubuntu-24.04-ga-kernel-nested-x86_64](evidence/doctor/ci-ubuntu-24.04-ga-kernel-nested-x86_64.json) |
| CI `ubuntu-24.04` runner (Ubuntu 24.04.5), x86_64 | 7.0.0-1017-azure | 8 | all 11 verified | 1, 2, 3 / 4 | [ci-ubuntu-24.04](evidence/doctor/ci-ubuntu-24.04.json) |
| CI `ubuntu-24.04-arm` runner (Ubuntu 24.04.5), aarch64 | 7.0.0-1017-azure | 8 | all 11 verified | 1, 2, 3 / 4 | [ci-ubuntu-24.04-arm](evidence/doctor/ci-ubuntu-24.04-arm.json) |
| CI `ubuntu-latest` runner (Ubuntu 26.04.1), x86_64 | 7.0.0-1019-azure | 8 | all 11 verified | 1, 2, 3, 4 / none | [ci-ubuntu-latest](evidence/doctor/ci-ubuntu-latest.json) |

The CI reports come from run
[43023705617](https://github.com/vignesh-chaturvedi/convergence/actions/runs/43023705617)
(commit `2d5ad24`, Python 3.12 jobs; the Python 3.13 jobs reported the same results).
No tested kernel offers ABI 9 or later, so those features remain `abi-only`.
