# ADR 0008 — Observation: strace as the tool's parent, every system call, no sandbox

**Status:** accepted · **Phase:** 5 · **Date:** 2026-11-12

## Context

`convergence observe` records what a tool does, so that `generate` can write a policy for
it. The record must cover:
- every file it opened, and how;
- every directory it listed, created in, or removed from;
- every program it executed;
- every port it connected to or bound;
- the full set of system calls it made.

Each fact must be citable.

Observation does not enforce anything, so the time-of-check/time-of-use problem that rules
out user notification as a *boundary* (THREAT_MODEL.md) does not apply here. What matters
is completeness and fidelity. Checked in the development VM with strace 6.8:

- With `-f -ff -yy`, strace writes one file per process. It prints each descriptor with the
  real path it refers to (`= 3</tmp/obs/out/new.txt>`) and each socket with its protocol
  (`3<TCP:[186039]>`). Relative paths in `*at` calls come with the directory they resolve
  against (`AT_FDCWD</tmp/obs>`).
- When strace starts the command itself, it is the command's parent, so Yama allows it
  without any exception.
- The kernel loads an ELF interpreter (`ld.so`) and a `#!` interpreter without a system call
  the tool makes, so no tracer sees those opens. Landlock still checks them (ADR 0006).

## Options considered

- **strace (chosen).** Mature decoders for every syscall on both architectures, real-path
  and socket decoding, and already a test dependency (`doctor` verifies it). Every syscall
  stops in the tracer, which is slow, but observation is a one-off.
- **seccomp user notification.** Fast, and selective. But the supervisor would have to read
  every pointer argument itself, which means reimplementing strace's decoders. It also needs
  `SECCOMP_FILTER_FLAG_NEW_LISTENER` in the tool, which the runtime denies.
- **A hand-written ptrace tracer.** Full control, but it is strace without strace's decades
  of argument decoding.
- **eBPF or fanotify.** These need privileges Convergence never asks for.

## Decision

- `convergence observe -- CMD` runs `strace -f -ff -yy -s 4096 -q -o <dir>/trace -- CMD`,
  started by the supervisor:
  - in a new session;
  - with `no_new_privs` and the default resource limits;
  - under the wall-clock timeout, after which the supervisor kills everything that is left.

  The tool keeps the caller's environment, working directory, and stdio.
- **It is not a sandbox, and says so** on every run: the tool has the user's full access.
  Run untrusted tools in a disposable VM.
- Events are taken from successful *and* failed calls. Failures matter for generation too: a
  connect refused by the network still needs the port, while a file that did not exist
  needs no grant. Repeated identical events are merged, with a count. Each kept event gets
  an id (`e12`) that generated rules cite.
- The ELF interpreter (from the executed file's `PT_INTERP`) and `#!` interpreters are added
  by `generate`, by reading the executed files; that is recorded in the rationale.
- Schema `convergence.observation/1` (`schemas/observation-v1.json`). An observation is
  marked `complete: true` only when it comes from strace and the run was neither timed out
  nor cut off by the event cap; an imported report is `partial`.

## Consequences

- Observation sees only the paths a run takes. A different input can take others; Phase 5
  measures this as the varied-input false-denial rate.
- Environment reads happen in user space and cannot be observed. `generate` passes a fixed
  set of standard variables and says so.
- Observing a tool runs it with the user's full access. This is the reason for the warning,
  and why `generate` can also start from a Divergence report produced inside Divergence's
  own sandbox.
