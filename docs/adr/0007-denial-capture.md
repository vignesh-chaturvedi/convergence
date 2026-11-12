# ADR 0007 — Denial capture: opt-in strace, attached from outside, contained by seccomp

**Status:** accepted · **Phase:** 4 · **Date:** 2026-11-12

## Context

When a sandboxed tool fails, the user needs to know which rule stopped it. The kernel does
not say: Landlock returns `EACCES`, seccomp returns `EPERM` (or `ENOSYS` for `clone3`), and
rlimits show up as `EAGAIN`, `EFBIG`, `EMFILE`, `ENOMEM`, `SIGXCPU`, or `SIGXFSZ`. The
failing system call has to be seen to be explained.

Facts checked on the development VM (Ubuntu 24.04.4, strace 6.8, Yama `ptrace_scope` 1) and
on the CI runners (strace 6.19):

- The tool is the supervisor's child (ADR 0006), so a tracer the supervisor starts is the
  tool's sibling. Yama scope 1 lets only an ancestor trace, unless the tracee names its
  tracer with `PR_SET_PTRACER`. That exception also covers the named process's descendants.
- Landlock lets a sandboxed process trace only processes in its own domain or one nested in
  it. Each `landlock_restrict_self` creates a new domain, so a tracer confined by Landlock
  can trace the tool only if the tool *inherited* the tracer's domain, which means the
  tracer, or a process in its domain, must be the tool's ancestor.
- `strace --seccomp-bpf` (stop only on chosen syscalls) works only when strace starts the
  tracee itself. Attached with `-p`, strace stops on every system call.
- strace reads the tracee's memory to decode arguments. A hostile tool controls that memory.

## Options considered

- **Trace by default, strace unconfined** (the original plan). A tool could attack strace's
  decoders, and strace runs with the user's full access. That would put a C parser of
  hostile input inside the trusted path of every run. It would also make the default
  configuration differ from the measured one: tracing changes process counts and timing.
- **strace as the tool's parent, inside a Landlock domain the tool inherits.** This contains
  strace by Landlock too, but the supervisor then loses the tool's exit status (strace
  reaps it), and a crash of strace kills the tool.
- **A hand-written ptrace or seccomp user-notification tracer.** That is ADR 0008's question
  (Phase 5, observe mode), not needed to explain denials now.
- **Opt-in strace, attached from outside, contained by `no_new_privs` and seccomp (chosen).**

## Decision

- `convergence run --trace` starts strace after forking the tool and before the tool applies
  its sandbox. The tool sets `PR_SET_PTRACER` to the supervisor and waits. The supervisor
  starts `strace -f -ff -q -y -e status=failed -p <tool>` and waits until the kernel shows the
  tool traced. Then it releases the tool, which clears the exception and continues. Children
  the tool forks are traced automatically.
- **strace is contained:**
  - it runs in its own session, with `no_new_privs`;
  - its seccomp filter denies `socket` and the built-in deny list, except the `ptrace` and
    `process_vm_readv` it needs;
  - its output goes only to a private directory that is removed after the run.

  It is not confined by Landlock (see above).
- **Never part of enforcement.** The sandbox is complete without strace. If strace is
  missing, cannot attach (Yama scope 2 or 3), or dies, the run continues untraced and the
  record says why. Tracing is off unless asked for, so the default configuration is the one
  the escape matrix measures.
- **Attribution** reads only failed calls and two signals:

  | Seen | Attributed to |
  |---|---|
  | `EACCES` on a Landlock-controlled path call, path outside every grant | Landlock filesystem |
  | `EXDEV` on rename or link, both paths on one filesystem | Landlock filesystem (`REFER`) |
  | `EACCES` on `connect` or `bind` | Landlock network |
  | `EPERM` on a syscall the filter denies | seccomp |
  | `EAGAIN` from `fork`/`clone` | `resources.max_processes` |
  | `EMFILE` | `resources.max_open_files` |
  | `EFBIG`, `SIGXFSZ` | `resources.max_file_size_mb` |
  | `ENOMEM` from memory calls | `resources.memory_mb` |
  | `SIGXCPU` | `resources.cpu_seconds` |
  | the deadline | `resources.wall_clock_seconds` |

  Anything else in that errno set is recorded as `unattributed`, never guessed. Examples
  are `EACCES` inside a grant (file permissions) and `EPERM` from another cause. Routine
  failures such as `ENOENT` are not denials and are not recorded. `clone3`'s `ENOSYS` is by
  design (ADR 0006) and is not recorded either.

## Consequences

- No denial detail unless `--trace` is given, and runs are slower with it: every system call
  of the tool stops in strace.
- A bug in strace's decoders can still be reached by a hostile tool. With seccomp it cannot
  open sockets or use the denied syscalls, but it can read and write the user's files. This
  is listed in THREAT_MODEL.md. Do not use `--trace` with a tool you would not trust with a
  debugger attached.
- Phase 5's observe mode needs a tracer anyway. ADR 0008 compares strace with a hand-written
  tracer and with seccomp user notification, and may replace this one.
