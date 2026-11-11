# ADR 0004 — Policy schema v1 and its enforceability model

**Status:** accepted · **Phase:** 2 · **Date:** 2026-11-11

## Context

The policy is the contract between a person (or a policy generator) and the kernel. Three
properties matter more than expressiveness:

- every rule must map to a kernel mechanism, so that whether a rule is enforced can be
  stated precisely for the running kernel;
- a policy must not mean something its author did not write (YAML coercion, duplicate keys);
- whatever cannot be enforced must be visible before anything runs.

What the mechanisms can express (Phase 1; [landlock-abi.md](../landlock-abi.md)):

- Landlock: allow-only filesystem rights on existing inodes, TCP ports from ABI 4, UDP
  ports from ABI 10, unix-socket and signal scoping from ABI 6 and 9;
- seccomp-bpf: syscall numbers and integer arguments, never pointer contents.

Neither mechanism can match a host name or IP address.

## Decision

**Format**

- YAML or JSON, `version: 1`, validated by a pydantic model in strict mode with
  `extra="forbid"`.
- Parsing goes YAML → plain data → JSON → strict validation. This rejects YAML-only values,
  so a value is never coerced.
- A custom loader rejects duplicate keys, anchors, and aliases, and the file size is capped
  at 1 MiB.
- The JSON Schema in `schemas/policy-v1.json` is generated from the model, and a test keeps
  the two in sync.

**Filesystem**

- Three buckets with fixed right sets (`docs/policy.md`): `read`, `write`, and `execute`
  (which implies read).
- `write` includes `IOCTL_DEV`, so device grants never depend on the ABI.
- `MAKE_CHAR`, `MAKE_BLOCK`, and `RESOLVE_UNIX` are never granted by a bucket.
- Paths are absolute, or start with `${HOME}`, `${CWD}`, or `${SCRATCH}`. `..` is not
  allowed. Missing paths are errors unless marked `optional`.
- Paths are resolved by following symlinks, the same way the runtime's `O_PATH` open will.
- `/proc/self` is resolved in the sandboxed process itself.

**Network**

- Per-direction port lists for TCP and UDP, each a list or `any`.
- A protocol with no ports at all is denied by seccomp on any kernel.
- Port-specific rules need Landlock ABI 4 (TCP) or 10 (UDP); on older kernels they are
  `unenforceable`. They are not approximated.
- `unix_sockets: deny` uses Landlock `RESOLVE_UNIX` plus abstract scoping where available
  (ABI 9 and up). Elsewhere it falls back to denying unix-socket creation, which is
  stricter than asked and reported as such.
- Host and IP allowlisting is out of scope for v1.

**Syscalls**

- A built-in deny list ([baseline.py](../../src/convergence/policy/baseline.py)) applies to
  every sandbox and cannot be weakened.
- Policies add denials, or switch to an allow list.
- Names are checked against libseccomp: unknown names are errors, and names that exist only
  on another architecture are notes.

**Resources**

- Rlimits per process, plus the supervisor's wall-clock limit.
- Memory defaults to `RLIMIT_DATA`, not `RLIMIT_AS`, because runtimes that reserve large
  virtual ranges (V8, Go) fail under `RLIMIT_AS`.
- `RLIMIT_NPROC` is per user, so `max_processes` is always reported with that caveat.

**Environment**

- The tool starts with an empty environment, plus the variables in `pass` and `set`.

**Enforceability**

- `explain` assigns each rule one of: `enforced`, `enforced-with-caveat`, `partial`,
  `unenforceable`, `skipped`, `not-available`.
- `run` (Phase 4) must refuse `partial` and `unenforceable` unless `--allow-degraded` is
  given, and must then list them.
- Capabilities come from `doctor`'s live probes. A feature the ABI reports but no probe has
  verified is at best `enforced-with-caveat`.
- **Baseline protections that no policy rule asks for** are reported as `not-available`
  when the kernel lacks them, and do not block a run. These are signal scoping before ABI
  6, and metadata operations (stat, chmod, chown, setxattr, utime) on every ABI.

## Consequences

- On stock Ubuntu 24.04 (ABI 4), a policy that allows DNS over UDP is `unenforceable`
  (UDP cannot be limited to port 53), and running it will need `--allow-degraded`. This is
  the price of failing closed. The `https-client` example demonstrates it.
- Read access to a device is `partial` before ABI 5 (ioctl cannot be denied). The example
  policies avoid device reads they do not need. `/dev/urandom` is unnecessary for Python,
  which uses `getrandom()`.
- Treating signal scoping and metadata gaps as reported baseline items, rather than
  blocking rules, keeps Convergence usable on ABI 4. It also means a sandboxed tool there can
  signal other same-user processes, and on any kernel can `chmod` files the user owns
  outside its grants. Both are stated in `explain`, `docs/policy.md`, and (Phase 3)
  `THREAT_MODEL.md`. Whether seccomp should mitigate the metadata gap is decided in Phase 4,
  with benign-control data.
- The built-in deny list and argument rules defined here are a commitment for Phase 4.
  If the runtime cannot implement a rule exactly, this ADR and `explain` must change with it.
