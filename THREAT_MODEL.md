# Threat model

> **Status:** draft, written in Phase 3 alongside the escape matrix and before the runtime
> exists ([PLAN.md](PLAN.md)). Every "defended" claim below becomes true only when the
> escape-matrix case that tests it passes against a real kernel (Phase 4). Until then, read
> this as the specification the runtime must meet, not a description of what it already does.

Convergence runs an AI agent tool — an MCP server, an agent skill, or a model-generated
script — under a least-privilege policy enforced by the Linux kernel (Landlock,
seccomp-bpf, resource limits, and an unprivileged supervisor). This document says what that
boundary defends against and, just as importantly, what it does not.

Convergence is **defence in depth, not a virtual-machine boundary.** It reduces what a tool
can do to what its policy grants. It is not a container, not a hypervisor, and not a defence
against a kernel exploit.

## The asset

What is being protected is the machine the agent runs on, and the data reachable from the
account it runs as: the user's files, credentials, other processes, and the network, beyond
what the tool's policy deliberately grants.

## The attacker

The attacker is the sandboxed tool itself. Assume the tool is fully hostile and that the
attacker:

- **runs arbitrary native code** of their choosing inside the sandbox — not just the
  advertised behaviour of the tool, but any syscall sequence they can assemble;
- **runs as the same unprivileged user** as the Convergence supervisor (no root, no
  capabilities on either side);
- **knows the policy** and knows that Convergence is in use, including this document and the
  source;
- **may fork, exec, and spawn** freely within what the policy and resource limits allow;
- **may be helped from outside** by a network peer on any host the policy lets it reach.

The attacker does **not** have root, does not start with any Linux capability, and cannot
load kernel code (that is denied — see below). Privilege escalation to root is out of scope
as an *assumed starting point*: if the tool can already become root by some other means, the
host is already lost and Convergence is not what stands in the way.

## Attacker goals, and what the policy is meant to deny

For a tool whose policy grants only what it needs, Convergence is meant to deny each of
these unless the policy explicitly allows it:

| Goal | Example | Defended by |
|---|---|---|
| Read data outside the grant | read `~/.ssh/id_ed25519`, `/etc/shadow`, another project's files | Landlock filesystem (ABI 1) |
| Write or destroy data outside the grant | overwrite `~/.bashrc`, delete files, write a cron entry | Landlock filesystem (ABI 1) |
| Reach the network beyond the grant | connect to an exfiltration host or an unlisted port; bind a port | Landlock TCP ports (ABI 4); seccomp for whole protocols |
| Escalate privilege | run a setuid binary to gain its owner's rights | `no_new_privs` (prctl) |
| Inspect or tamper with other processes | `ptrace`, `process_vm_readv`, `/proc/<pid>/mem`, signals | seccomp; Landlock signal scope (ABI 6); ptrace domain rules |
| Escape the confinement | `mount`, `pivot_root`, `chroot`, `unshare`, `setns`, namespace `clone` | seccomp deny list |
| Bypass the syscall filter | `io_uring` submission queue, a foreign-architecture syscall, `seccomp` user-notify | seccomp (deny `io_uring_*`, kill on bad arch, deny `NEW_LISTENER`) |
| Deny service to the host | fork bomb, memory or CPU exhaustion, fill a disk, exhaust file descriptors | rlimits + the wall-clock supervisor |
| Persist beyond the run | a double-forked or `setsid` daemon that outlives the tool | supervisor: subreaper + process-group kill |
| Steal ambient secrets | read the supervisor's environment, or an inherited file descriptor | supervisor: empty environment, close inherited fds |

Each row corresponds to one or more escape-matrix categories
([escape/README.md](escape/README.md)). "Defended by" names the mechanism; whether it holds
on a given kernel is what the matrix measures.

## What is enforced, by mechanism

- **Landlock** confines the filesystem to the policy's granted paths, and (from ABI 4) TCP
  bind and connect to the granted ports. Rules attach to inodes, so symlink, `..`, and
  rename tricks do not widen access.
- **seccomp-bpf** installs a kernel-only filter (never user-notification as a security
  boundary; see below). It denies a fixed list of escape- and tamper-prone syscalls,
  restricts socket families, types, and protocols to what the network policy grants (so
  SCTP, MPTCP, UDP-Lite, and ICMP cannot bypass Landlock's TCP and UDP rules), and applies
  integer-argument rules (namespace flags on `clone`, `TIOCSTI`/`TIOCLINUX` on `ioctl`,
  `NEW_LISTENER` on `seccomp`, `personality` flags that disable address-space randomisation
  or make memory executable). Arguments the kernel truncates to 32 bits are compared so that
  setting the high bits cannot slip past a rule. Foreign-architecture syscalls hit the kill
  action.
- **`no_new_privs`** stops a setuid or file-capability binary from raising privileges, and is
  required for unprivileged seccomp.
- **Resource limits** (`RLIMIT_*`) bound CPU time, private memory, file size, open files, and
  processes.
- **The supervisor** gives the child an empty environment plus only the policy's variables,
  closes every inherited descriptor above stderr, starts a new session with no controlling
  terminal, and becomes a subreaper. When the tool's first process exits, or at the
  wall-clock deadline, it kills the process group and every remaining descendant, including
  daemons that left the session. Core dumps are disabled. The spawn sequence is in
  [ADR 0006](docs/adr/0006-spawn-model.md).

## Why not seccomp user notification for argument checks

seccomp user notification (`SECCOMP_RET_USER_NOTIF`) lets a supervisor inspect a syscall's
arguments in user space and allow or deny it. Convergence does **not** use it as a security
boundary. Pointer arguments such as paths and socket addresses are read from the target's
memory, and between the supervisor's check and the kernel's use of them the target (or a
thread it controls) can change them — a time-of-check/time-of-use race the kernel's own
`seccomp_unotify` documentation warns about. Convergence enforces with Landlock (which the
kernel evaluates atomically) and with seccomp-bpf on **integer** arguments only. User
notification may later be used for observation and logging, where a race cannot grant
access.

## Explicit non-goals

Convergence does **not** defend against these. They are out of scope by design, not
oversights:

1. **Kernel exploits.** A bug in Landlock, seccomp, or any syscall the policy allows can
   defeat the boundary. Convergence shares the host kernel; a kernel compromise is total.
2. **Side channels and covert channels.** Timing, cache, `/proc` and `/sys` readings that
   remain allowed, speculative execution, and resource-contention signals are not addressed.
3. **Host or IP allowlisting (v1).** Landlock filters by **port, not host**. A policy that
   allows TCP 443 allows HTTPS to every host. Exfiltration to an arbitrary host over an
   allowed port is not prevented. Restricting destinations needs a mechanism outside v1's
   scope, and Convergence does not fake it.
4. **Misuse of what the policy grants.** If the policy grants write to a directory, the tool
   may corrupt anything in it. If it grants a port, the tool may do anything on it. The
   boundary is only as tight as the policy; a loose policy is a loose sandbox. Convergence's
   `generate` (Phase 5) and `validate` exist to keep policies tight, but the policy is the
   contract.
5. **Data already reachable before confinement.** Secrets passed in through the environment,
   arguments, or granted files are available to the tool by definition.
6. **DNS.** On stock Ubuntu 24.04 (Landlock ABI 4), UDP cannot be limited to port 53, so a
   policy needing DNS over UDP either runs degraded or uses DNS over TCP. Where UDP is
   allowed at all, it reaches any host (see non-goal 3).

## Known limitations that depend on the kernel ABI

These are real gaps on some kernels. `convergence explain` reports each on the running
kernel, and the escape matrix records them as **documented limitations**, not as surprise
escapes:

- **Signals to same-user processes.** Scoping signals to the sandbox needs Landlock ABI 6.
  On ABI 4 (stock Ubuntu 24.04) a sandboxed tool can send signals to other processes run by
  the same user. Enforced from ABI 6.
- **File metadata.** On **every** ABI, Landlock does not control `stat`, `access`, `chdir`,
  `chmod`, `chown`, `setxattr`, or `utime` (stated in the kernel's
  `include/uapi/linux/landlock.h`). A sandboxed tool can learn that files exist outside its
  grants and read their metadata, and can change the permissions, ownership, extended
  attributes, and timestamps of files the user owns anywhere on the system. It cannot read
  or modify their **contents**. Whether seccomp should mitigate the metadata-change subset
  (`chmod`, `chown`, `setxattr`, `utime`) is decided in Phase 4 using the benign controls as
  evidence, because a blanket denial can break ordinary tools (`tar`, `pip`, `touch`).
- **Abstract and pathname unix sockets.** Scoping unix-socket connections to the sandbox
  needs ABI 6 (abstract) and ABI 9 (pathname). Below those, Convergence denies unix-socket
  *creation* entirely (seccomp), which is stricter than asked; `socketpair()` still works.
- **Device `ioctl`.** Restricting `ioctl` on a device the tool may read needs ABI 5. Below
  it, a readable device can still receive driver `ioctl`s. Convergence's `write` grants
  always include device `ioctl`; a *read-only* device grant is only partial before ABI 5,
  which `explain` reports.

## Residual risks even when everything is enforced

- **Execute grants do not limit code the tool can read (measured: `exec-via-loader-001`
  and the holdout's `holdout-exec-via-loader-001` escape).** The kernel checks Landlock's execute right when it starts a program, including
  the dynamic loader of every dynamically linked binary. So the loader must be granted
  execute for anything to run. Running `ld.so <binary>` then maps a program the tool can
  only *read*, and Landlock never checks memory mapped as executable. The same holds for an
  interpreter loading a readable script or shared library, and for code the tool writes into
  memory. Execute grants decide which programs the kernel will start directly; they are not
  a boundary against running code the tool can read. Everything that runs this way still
  runs inside the same sandbox, so it gains no access the tool did not already have. Grant
  read narrowly if a readable binary would be dangerous to run.
- **Denial capture runs outside the sandbox.** `convergence run --trace` attaches strace to
  the tool from outside (ADR 0007). strace decodes memory the tool controls. It runs with
  `no_new_privs` and a seccomp filter that denies sockets and the dangerous syscalls it does
  not need, but it keeps the user's file access, so a bug in its decoders could be used to
  escape. Tracing is off by default, and the escape matrix measures the default.
- **The MCP server chooses nothing itself.** `convergence mcp`, its spawn helper, and its
  workers run unconfined, like the CLI's supervisor (ADR 0010). Their attack surface is the
  JSON they parse and the policies they load. A client allowed to send inline policies
  (`--allow-inline-policy`) chooses its own sandbox. That is why the default is the
  operator's `--policies` directory.
- **A supervisor killed with `SIGKILL`.** The tool's first process dies with it
  (`PR_SET_PDEATHSIG`). Processes the tool started are re-parented to the next subreaper or
  to init, and keep running inside the sandbox until they exit. Stopping the supervisor any
  other way (Ctrl-C, `SIGTERM`, `SIGHUP`) kills everything.
- **`RLIMIT_NPROC` is per user, not per sandbox.** The process limit counts every process the
  user owns. Convergence sets it relative to the count at launch, but a fork bomb's
  containment also leans on the wall-clock deadline and the process-group kill, not on the
  rlimit alone.
- **Resource limits are coarse.** They bound a single run; they do not meter aggregate I/O or
  prevent a tool from using exactly as much of a granted resource as the limit allows.

## How this document is kept honest

Every defended claim is tied to an escape-matrix case with an **external oracle** — ground
truth the harness checks, never the payload's own report. The matrix reports two numbers,
the **escape rate** (attacks the sandbox failed to block) and the **false-denial rate**
(benign workloads the sandbox wrongly blocked), measured on real kernels with no mocks. Any
attack that is not blocked is either fixed or listed here as a known limitation with its
reason. The README carries no claim the matrix does not support.
