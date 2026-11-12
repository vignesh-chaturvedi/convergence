# ADR 0006 — Spawn model: build in the parent, apply in a single-threaded child, supervise

**Status:** accepted · **Phase:** 4 · **Date:** 2026-11-12

## Context

`convergence run` must start one command with Landlock, seccomp, `no_new_privs`, and
resource limits applied before its first instruction runs. It then has to contain everything
the command starts: enforce the wall clock, and leave nothing behind. All of it is Python
(ADR 0001), so the code between `fork` and `execve` is the interpreter running bytecode.

Checked on the development VM (Ubuntu 24.04.4, kernel 6.8.0-134, aarch64, libseccomp
2.5.5):

- libseccomp refuses a rule that compares one argument twice (`EINVAL`) and two rules with
  different actions for one syscall (`EACCES`). "Allow this syscall except for these
  argument values" therefore cannot be one filter in allow-list mode.
- The kernel runs every installed seccomp filter and applies the most restrictive action
  (`kernel/seccomp.c`, `seccomp_run_filters`). For equal actions it keeps the newest filter's
  value.
- A forked child inherits the parent's address space. The supervisor's data segment is
  larger than a small `RLIMIT_DATA` (the `resource-memory` case allows 32 MiB). Once that
  limit is set, any new allocation in the child fails, so nothing may allocate between
  `setrlimit` and `execve`.
- `fork` in a multi-threaded process copies only the calling thread. Locks held by other
  threads stay locked in the child.
- The kernel truncates some arguments to 32 bits (`ioctl` request, `socket` family, type,
  and protocol, `personality`), but seccomp sees the full 64-bit register. A rule that
  compares all 64 bits can be bypassed by setting the high bits (`TIOCSTI | 1 << 32`).

## Options considered

- **`subprocess.Popen` with `preexec_fn`.** Popen does the pipes and error reporting. But
  `preexec_fn` runs before Popen closes descriptors and does its own allocations around
  it, and it is documented as unsafe with threads.
- **A small C or Rust helper.** It would be exact between `fork` and `execve`. But it is
  another language and build, which ADR 0001 rules out for v1.
- **Own `fork`, with everything that allocates done before the fragile part (chosen).**
  The parent builds every object the child needs. The child runs a fixed sequence, and its
  last three steps go through prebuilt ctypes objects.

## Decision

**Parent, before `fork`:**
1. Load and validate the policy.
2. Assess it against the running kernel, and refuse a policy with `partial` or
   `unenforceable` rules unless `--allow-degraded` is given.
3. Open every granted path `O_PATH`, choose its rights from the opened file's real type, and
   build the Landlock ruleset.
4. Compile the seccomp programs with libseccomp, resolve the executable, and build the
   environment.
5. Prebuild the ctypes `argv`, `envp`, `rlimit`, and `sock_fprog` objects.

The supervisor is single-threaded when it forks. Its output relay threads start only
afterwards.

**Child, in order:**
1. `setsid`, reset ignored signals and the signal mask, connect stdio, and `chdir`.
2. Set `PR_SET_PDEATHSIG`, so the tool dies with the supervisor, then `no_new_privs`.
3. Add the `/proc/self` rules, which only the child can resolve, then
   `landlock_restrict_self`.
4. Mark every descriptor above 2 close-on-exec (`close_range`).
5. Through prebuilt objects only: the rlimits, the seccomp programs, then `execve`.

A failure is reported to the parent on a close-on-exec pipe as a step code and errno.

**Seccomp, as two filters:**
- The **baseline filter** allows by default and lists only denials: the built-in deny list,
  the policy's `deny`, and argument patterns. Each argument pattern is written as rules that
  cover exactly the denied values. A 32-bit argument is compared through a 32-bit mask, or
  with a comparison that denies when the high bits are set.
- In **allow-list mode**, a second filter denies by default and allows the policy's list.
  It always also allows `execve`, `exit` and `exit_group`, so the launch can finish and the
  tool can exit. `clone3` fails with `ENOSYS` there too, so the C library falls back to
  `clone`.

**Supervisor:**
- It is a child subreaper, so every orphan of the sandbox becomes its child.
- When the tool's first process exits, the run is over. So is the wall-clock deadline or a
  signal to the supervisor. In each case the supervisor kills the tool's process group and
  then sweeps every descendant, until none is running.
- **The sweep (changed after the security review of 0.1.0).** The first version killed and
  reaped only the supervisor's direct children, round after round. A tool that kept forking
  into new sessions stayed ahead of it: a 3-second limit ended after 270 seconds, with 41
  processes left. Now:
  - the sweep walks the whole process tree and signals parents before their children;
  - nothing is reaped until everything is dead. A dead process keeps its `RLIMIT_NPROC`
    slot until it is reaped, so every fork the tool wins uses up a slot for good, and a
    parent that is already dying cannot free one by reaping;
  - each process is opened as a `/proc/<pid>` directory, checked to be a child of the
    process it was listed under, and signalled through that descriptor. A reused pid is
    never signalled;
  - the first process is reaped last, so its process-group id cannot be reused meanwhile.
- The sweep relies on `resources.max_processes`. Without it, it gives up after 10 seconds
  and the run record says how many processes are left (`outcome.left_running`).
- Stop signals are blocked across the fork, so neither process handles one before the
  child's pid is stored.

## Consequences

- No compiled code; the whole launch path is readable Python.
- The fragile section is short and allocation-free in practice, but CPython gives no
  guarantee. If an allocation there fails, the child reports what it can and exits; the
  tool never runs unconfined.
- In allow-list mode, a policy that does not allow `write` cannot report an `execve`
  failure. The run then fails with exit code 126 and no detail.
- The tool runs only as long as its first process. Background processes are killed when it
  exits; a tool that must leave a daemon running cannot be run this way.
- If the supervisor is killed with `SIGKILL`, the first process dies with it
  (`PR_SET_PDEATHSIG`). Its descendants are re-parented to the next subreaper or to init,
  and survive. This is documented in THREAT_MODEL.md.
- `RLIMIT_CORE` is set to 0, so a crash in the sandbox never writes memory into a core file.
