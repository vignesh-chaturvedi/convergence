# Policy format (`convergence.policy/1`)

A policy says what a tool may do. **Everything it does not grant is denied.** Policies are
YAML or JSON files, and validation is strict:

- unknown keys are errors;
- no value is coerced: `"443"` is not a port, and `true` is not a version number;
- duplicate YAML keys are errors (YAML would otherwise keep the last one silently);
- YAML anchors and aliases are not allowed;
- only plain JSON data is accepted, so YAML dates and similar values are errors.

The machine-readable schema is [`schemas/policy-v1.json`](../schemas/policy-v1.json).

> **Status:** `validate` and `explain` exist. `convergence run`, which enforces policies,
> arrives in Phase 4 ([PLAN.md](../PLAN.md)). This page specifies what a policy will mean
> when it runs. `explain` already reports how each rule would be enforced on your kernel.

## Example

```yaml
version: 1
name: python-offline
description: Python script reading ${CWD}, writing to ${SCRATCH}, no network.

filesystem:
  read: [/usr, /etc/ld.so.cache, "${CWD}"]
  write: ["${SCRATCH}", /dev/null]
  execute:
    - /usr/bin/python3
    - {path: /usr/lib/ld-linux-aarch64.so.1, optional: true}
    - {path: /usr/lib64/ld-linux-x86-64.so.2, optional: true}

network: {}            # no TCP, no UDP, no unix sockets outside the sandbox

resources:
  wall_clock_seconds: 60
  cpu_seconds: 30

environment:
  set: {PATH: /usr/bin:/bin, HOME: "${SCRATCH}", LANG: C.UTF-8}
```

More examples are in [`examples/policies/`](../examples/policies/).

## `filesystem`

Three lists of paths: `read`, `write`, and `execute`. A directory grants access to
everything beneath it. A file grants access to that file only.

| Bucket | On a file | On a directory, additionally |
|---|---|---|
| `read` | `READ_FILE` | `READ_DIR` (list entries) |
| `write` | `READ_FILE`, `WRITE_FILE`, `TRUNCATE`, `IOCTL_DEV` | `READ_DIR`, `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM`, `MAKE_FIFO`, `MAKE_SOCK`, `REMOVE_FILE`, `REMOVE_DIR`, `REFER` |
| `execute` | `EXECUTE`, `READ_FILE` | `READ_DIR` |

These are Landlock access rights ([landlock-abi.md](landlock-abi.md)). A right the running
kernel does not know is not requested. `MAKE_CHAR` and `MAKE_BLOCK` (creating device nodes)
are never granted. `RESOLVE_UNIX` (connecting to pathname unix sockets) is controlled by
`network.unix_sockets`, not by filesystem grants.

**Paths**

- A path must be absolute, or start with one of these variables:
  - `${HOME}`: the caller's home directory;
  - `${CWD}`: the directory the tool runs in;
  - `${SCRATCH}`: a fresh, empty directory created for each run and removed afterwards.
    Only `${SCRATCH}` itself can be granted, because paths beneath it do not exist when the
    sandbox starts.
- `..` is not allowed.
- An entry can be a string, or `{path: ..., optional: true}`. An optional path that does not
  exist is skipped. Any other missing path is an error.
- **A path must exist when the sandbox starts.** Landlock attaches each rule to the inode the
  path refers to, after following symlinks. To let a tool create `out.txt`, grant `write` on
  the directory that will contain it.
- Because rules attach to inodes, renaming a path or reaching it through a symlink changes
  nothing: the kernel checks the file's position in the real hierarchy.
- `/proc/self` (and `/proc/thread-self`) are resolved inside the sandboxed process when it
  starts. They cover that process only, not processes it starts later.

**What a policy cannot express.** Landlock is allow-only, so you cannot grant a directory
and then exclude a subdirectory such as `~/.ssh`. Grant narrower paths instead. `validate`
warns when a grant contains your home directory or a known credential location.

## `network`

| Key | Meaning | Default |
|---|---|---|
| `tcp_connect` | remote TCP ports that may be connected to, on **any host**; or `any` | `[]` |
| `tcp_bind` | local TCP ports that may be bound (`0` = an ephemeral port); or `any` | `[]` |
| `udp_send` | remote UDP ports that may be sent to, on any host; or `any` | `[]` |
| `udp_bind` | local UDP ports that may be bound; or `any` | `[]` |
| `unix_sockets` | `deny`: no connections to unix sockets outside the sandbox. `allow`: unrestricted | `deny` |

- **Ports, not hosts.** Landlock filters by port number. `tcp_connect: [443]` allows HTTPS to
  every host on the internet. Restricting hosts or IP addresses is **out of scope for v1**,
  because no unprivileged kernel mechanism Convergence uses can express it, and Convergence
  does not fake it.
- When nothing is granted for a protocol (for example no UDP port at all), seccomp denies
  creating sockets of that kind, which works on any kernel. Limiting a protocol *by port*
  needs Landlock: ABI 4 for TCP, ABI 10 for UDP. On an older kernel such a rule is
  `unenforceable`.
- `unix_sockets: deny` is enforced exactly from Landlock ABI 9 on (`RESOLVE_UNIX` plus
  abstract-socket scoping). On older kernels Convergence denies creating unix sockets
  altogether. That is stricter than asked, so `explain` reports `enforced-with-caveat`.
  `socketpair()` keeps working.
- `unix_sockets: allow` lets the tool reach host services such as a container runtime socket
  (root-equivalent) or the session bus. `validate` warns about it.

## `syscalls`

| Key | Meaning |
|---|---|
| `mode: deny-list` (default) | Everything is allowed except the built-in deny list and `deny`. |
| `mode: allow-list` | Only `allow` is permitted. The built-in deny list still applies. |
| `deny` | extra syscalls to deny (with `EPERM`) |
| `allow` | allow-list mode only: every syscall the tool may make |

Names are checked against libseccomp when you run `validate`:
- a name libseccomp does not know is an error (a typo, or a syscall newer than the installed
  libseccomp);
- a syscall that exists only on another architecture is a note, and has no effect here.

**Built-in deny list.** It applies in both modes. It cannot be weakened by a policy.

| Syscalls | Why |
|---|---|
| `ptrace`, `kcmp` | trace or inspect other processes |
| `process_vm_readv`, `process_vm_writev`, `process_madvise`, `pidfd_getfd`, `migrate_pages`, `move_pages` | read or change another process's memory or file descriptors |
| `mount`, `umount2`, `pivot_root`, `chroot`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr` | mount filesystems or change the root |
| `unshare`, `setns` | create or enter namespaces |
| `clone3` (fails with `ENOSYS`) | its flags live in a structure seccomp cannot inspect; the C library falls back to `clone`, whose flags are checked |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | io_uring operations are not seen by seccomp |
| `bpf`, `perf_event_open`, `userfaultfd`, `fanotify_init` | large kernel attack surface |
| `keyctl`, `add_key`, `request_key` | kernel keyrings are shared with the user's session |
| `open_by_handle_at`, `name_to_handle_at` | open files by handle, bypassing path checks |
| `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `vhangup`, `settimeofday`, `clock_settime`, `sethostname`, `setdomainname` | privileged administration |
| `lookup_dcookie`, `nfsservctl`, `uselib`, `ustat`, `sysfs`, `_sysctl`, `iopl`, `ioperm`, `modify_ldt`, `vm86`, `vm86old` | obsolete or x86-specific |

Argument checks on syscalls that otherwise stay allowed:
- `clone` is denied when its flags create a namespace;
- `seccomp` is denied when it would install a user-notification listener;
- `ioctl` `TIOCSTI` and `TIOCLINUX` (terminal input injection) are denied;
- `personality` is limited to queries and the values Docker's default profile allows;
- `socket` is limited to the families and types the network policy grants.

## `resources`

| Key | Mechanism | Default |
|---|---|---|
| `wall_clock_seconds` | the supervisor kills the whole sandbox (process group and every descendant) | 60 |
| `cpu_seconds` | `RLIMIT_CPU`, per process | 60 |
| `memory_mb` | `RLIMIT_DATA`, per process: heap and other private writable memory. Not a cgroup limit | 2048 |
| `address_space_mb` | `RLIMIT_AS`, per process. Off by default: V8 and Go reserve large virtual ranges | off |
| `max_processes` | `RLIMIT_NPROC`. **The kernel counts this per user, not per sandbox**; it is set to your current process count plus this value at launch | 64 |
| `max_file_size_mb` | `RLIMIT_FSIZE` | 1024 |
| `max_open_files` | `RLIMIT_NOFILE` | 1024 |

`null` turns a limit off, except `wall_clock_seconds`, which is required and at most 24 hours.

## `environment`

The tool starts with an **empty environment** plus:
- `pass`: names copied from the caller's environment, if set;
- `set`: fixed values.

A name cannot be in both lists. `validate` warns about names that look like secrets
(`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, and similar). It notes when `PATH` is
missing.

## Enforceability: `explain`

```bash
convergence explain --policy p.yaml            # this kernel, from live probes
convergence explain --policy p.yaml --json
convergence explain --policy p.yaml --assume-abi 6   # a hypothetical kernel; nothing verified
```

Every rule gets a status:

| Status | Meaning | Blocks `run`? |
|---|---|---|
| `enforced` | enforced as written | no |
| `enforced-with-caveat` | enforced, with a stated difference: stricter than asked, or in the kernel's ABI but not yet proven by a live probe | no |
| `partial` | part of the rule is not enforced | **yes** |
| `unenforceable` | this kernel cannot enforce the rule | **yes** |
| `skipped` | an optional path that does not exist | no |
| `not-available` | a baseline protection this kernel lacks (see below) | no; reported |

**Fail closed.** `run` will refuse a policy with any `partial` or `unenforceable` rule unless
you pass `--allow-degraded`, and then it prints exactly those rules. A rule is never dropped
silently.

**Baseline protections** apply to every sandbox, whatever the policy says:
- the default-deny filesystem;
- the built-in syscall deny list;
- `no_new_privs`;
- no inherited file descriptors.

The ones a kernel cannot provide are listed as `not-available` rather than blocking, because
no policy rule asks for them. Two of them are worth knowing:

- **Signals.** Before Landlock ABI 6, a sandboxed tool can send signals to other processes run
  by the same user.
- **File metadata.** On every kernel, Landlock does not control `stat`, `access`, `chdir`,
  `chmod`, `chown`, `setxattr`, or `utime` (see the warning in the kernel's
  `include/uapi/linux/landlock.h`). A sandboxed tool can see whether files exist outside its
  grants, and can change the permissions and timestamps of files you own. It still cannot
  read or change their contents. Convergence does not mitigate this yet.

## `validate`

```bash
convergence validate p.yaml          # exit 0 valid, 1 invalid
convergence validate p.yaml --json   # schema convergence.validation/1
```

`validate` reports:
- **errors**: the schema, missing paths, unknown syscall names;
- **warnings**: valid but risky grants, such as:
  - the whole filesystem;
  - your home directory or a credential directory such as `~/.ssh`, `~/.aws`, or `~/.config/gh`;
  - `/proc`, `/sys`, or all of `/dev`;
  - writes to system directories;
  - `any` ports or `unix_sockets: allow`;
  - variables that look like secrets;
- **notes**: worth knowing, such as symlink targets, the per-user process limit, and that
  port rules apply to every host.

Warnings never change what a policy means.
