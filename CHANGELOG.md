# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it is released.

## [Unreleased]

### Added

- `convergence run --policy P -- COMMAND`: runs a command under a policy with Landlock
  (files, TCP/UDP ports, signal and abstract-socket scoping), a seccomp filter, `no_new_privs`,
  and rlimits. The tool gets an environment built only from the policy and no inherited
  descriptors beyond stdio. A policy the kernel cannot fully enforce is refused unless
  `--allow-degraded` is given; the degraded rules are then listed. Options: `--timeout`,
  `--json`, `--max-output`, `--no-record`. Exit status: the tool's own, 128+N for a signal,
  124 for the wall clock, 125 not started, 126 cannot execute, 127 not found.
- Supervision: the supervisor is a child subreaper. When the tool's first process exits, at
  the wall clock, or when the supervisor is stopped, it kills the process group and every
  remaining descendant, including daemons that left the session. The tool dies with a killed
  supervisor (`PR_SET_PDEATHSIG`). Core dumps are disabled.
- Run records (`convergence.run/1`, `schemas/run-v1.json`), saved privately under
  `$XDG_STATE_HOME/convergence/runs/`.
- `convergence run --trace`: denial capture with strace (ADR 0007). The tool names the
  supervisor as its tracer and waits until strace has attached. strace runs in its own
  session with `no_new_privs` and a seccomp filter (no sockets, no denied syscalls beyond
  `ptrace` and `process_vm_readv`). Each failed operation is attributed to Landlock
  filesystem or network, seccomp, an rlimit, or the deadline, or recorded as
  `unattributed`. Tracing is opt-in, not the default the plan proposed: strace parses memory
  the tool controls while holding the user's file access. If strace is missing or cannot
  attach, the run goes on untraced and the record says why.
- The holdout's one run under Convergence, committed as it came out: 21 pass, 1 escape (the
  dynamic-loader limitation), 1 documented limitation (ABI 6), 3 `not-reached`; escape rate
  1/22.
- `escape/known-limitations.yaml`: development cases that escape by design, each with its
  reason and THREAT_MODEL.md section. They are reported as `known-limitation`, count in the
  escape rate, and do not fail the run; the list never applies to the holdout. The CI escape
  job's confined run is now required.
- ADR 0006: the spawn model. The ruleset and seccomp programs are built in the parent, and
  the child applies them in a fixed order. Its last steps (rlimits, seccomp, `execve`) use
  only prebuilt objects, because a small `RLIMIT_DATA` would make any allocation fail.
- The seccomp filter is two filters, because libseccomp cannot express "allow except these
  argument values" in one. A baseline filter lists only denials: syscalls, namespace flags
  on `clone`, `TIOCSTI`/`TIOCLINUX`, the seccomp listener flag, `personality` flags that
  disable address-space randomisation, and every socket family, type, or protocol the policy
  does not grant. Allow-list mode adds a second, deny-by-default filter. Arguments the kernel
  reads as 32-bit values are compared so that high bits cannot slip past a rule.
- Escape matrix under `convergence run` on the stock Ubuntu 24.04 kernel: 53 development
  attacks pass, 1 escape (the dynamic-loader limitation, now documented in
  THREAT_MODEL.md), 1 documented limitation (signal scoping needs Landlock ABI 6), and all
  10 controls pass.

- Development attack corpus: 47 distinct cases generated from one explicit table by
  `escape/build_cases.py`. The generator writes development cases only, refuses duplicates,
  never touches files it did not create, and a test fails if a generated file is edited by
  hand. On the stock Ubuntu 24.04 kernel 45 are valid unconfined and 2 are not testable.
- Sealed holdout: 26 attack cases written independently of the generator and of the
  runtime, all valid unconfined, with the manifest `escape/cases/holdout.sha256` and every
  validity run recorded in `escape/holdout-runs.jsonl`. It replaces the first holdout,
  which repeated development cases.
- `process-read` options `secret_in_mapped_path` (the secret is the name of a file the
  sentinel maps, visible in `/proc/<pid>/maps`) and `expose_secret_address` (the sentinel
  reports the secret's address as `${SENTINEL_SECRET_ADDR}`). At most one alternate source
  per case.
- `process-read` option `secret_in_environment`: the sentinel also holds its secret in its
  environment, so a case can target `/proc/<pid>/environ` (a ptrace read check) as well as
  `/proc/<pid>/mem` (an attach check). Only `process-read` accepts it.
- Oracles that isolate syscall-filter mechanisms: `fd-kind` (an io_uring, userfaultfd,
  perf_event, or BPF descriptor appeared), `namespace-change` (a process entered a new
  namespace), and `key-created` (this user's key count rose).
- Host preconditions: `userns-create`, `io-uring`, `userfaultfd`, `unprivileged-bpf`,
  `unprivileged-perf` (each probed by a real syscall in a throwaway child, numbers from
  libseccomp), plus `raw-socket` and `setuid-executable`. Preconditions are probed lazily,
  once per process, and only for the selected cases.

### Fixed

- Escape harness: per-process measurements (memory, CPU, descriptors) no longer include the
  launcher's own process. Under Convergence that process is the supervisor, which would have
  counted as the tool.
- Development cases `net-udp-001` and `unix-socket-host-001` now signal `${REACHED}` before
  creating the socket, which is the step their mechanism stops. `setuid-no-new-privs-001`
  now grants the pseudo-terminal its setup needs. The `control-tar-gzip` policy grants
  `/bin/sh`, which GNU tar uses to start the compressor.
- `exec-probe`'s marker failed on Ubuntu 26.04, whose Rust uutils `sleep` is a multi-call
  binary that picks its tool from its own name: copied as `marker`, it exited at once and was
  never sampled. The copy is now named `sleep` and checked during setup. The escape job now
  also runs on `ubuntu-latest` (Ubuntu 26.04).
- On Ubuntu 26.04 `exec-via-loader-001` was invalid: an Ubuntu patch makes uutils refuse to
  run unless the tool name matches the executable the kernel started, which through the
  dynamic loader is `ld.so`. Setup now checks each candidate both directly and through the
  loader and takes the first that works; there that is GNU's `/usr/bin/gnusleep`. The
  loader route now has its own test.
- The process sampler now includes setuid processes (their `/proc/<pid>` is owned by root),
  so `privilege-gain` can fire; the unconfined safety limit counts threads, which is what
  `RLIMIT_NPROC` charges.
- `resource-dos` with `measure: processes` compared all processes with `max_processes`; it now
  counts the processes added beyond the tool's own, as the policy defines it. A correctly
  enforced limit would otherwise have been scored as an escape.
- Oracle configuration is validated through JSON, so list-valued settings work.
- The holdout run record is `escape/holdout-runs.jsonl`; the old `.log` name was git-ignored.
- Escape-case payloads are excluded from ruff and mypy: they are fixtures, and the holdout
  ones are sealed by hash.
- Escape-matrix harness additions:
  - unix-socket sinks (`network-sink` with `family: unix` or `unix-abstract`), standing in
    for a host service outside the sandbox;
  - host preconditions (`platforms.requires`: `unprivileged-userns`, `legacy-tiocsti`),
    probed by trying the behaviour in a throwaway child. A case the host already prevents is
    `not-testable`, never counted as blocked. On the Ubuntu 24.04 VM both are refused;
  - a mandatory `${REACHED}` marker for attacks. Contained without it is `not-reached` (a
    failure); escaping unconfined without it is `invalid`; an escape is never excused.
- Escape-matrix harness (`escape/`), outside the installed package:
  - a strict case format (`convergence.escapecase/1`) with an ABI-aware expected verdict;
  - `${VARIABLE}` expansion: strict in policies and argv, lenient in shell payload files;
  - a `/proc` sampler that tracks a run's processes by pid and start time, including
    daemons reparented to the runner as a child subreaper;
  - unconfined and Convergence launchers. The unconfined launcher runs inside a safety
    envelope of rlimits at four times the policy's; the Convergence launcher reports
    `launcher-unavailable` until `convergence run` exists, never a silent pass;
  - fourteen external oracles: planted secrets, forbidden paths, held-open sentinel files,
    harness-owned network sinks, sentinel processes, executable-mapping detection, resource
    measurement, and survivors;
  - scoring with Wilson 95% intervals, JSON and Markdown reports, and a SHA-256 holdout seal
    with a one-time `--holdout-run` gate and a run log.
- Ten benign controls (`controls/`): Python, git, a shell pipeline, tar and gzip, sqlite3,
  json.tool, byte-compilation, an HTTP client and a TCP server on granted ports, and a
  process-spawning tool. All ten are valid unconfined.
- `THREAT_MODEL.md` (draft), ADR 0005, and the escape-matrix specification
  (`escape/README.md`).
- Committed reports in `escape/results/`: the unconfined validity run (10/10 controls valid)
  and the initially-red confined baseline.
- CI `escape` job on `ubuntu-24.04` and `ubuntu-24.04-arm`: holdout seal check, the validity
  gate (required), and the confined matrix (allowed to fail until Phase 4).
- Policy format `convergence.policy/1` (YAML or JSON): `filesystem` (read, write, execute
  with `${HOME}`, `${CWD}`, `${SCRATCH}`, and optional paths), `network` (TCP and UDP ports
  per direction, unix sockets), `syscalls` (deny list or allow list on top of a built-in deny
  list), `resources` (wall clock and rlimits), and `environment` (empty unless passed or
  set). Strict validation: unknown keys, coercion, duplicate YAML keys, anchors, aliases, and
  non-JSON values are errors. JSON Schema in `schemas/policy-v1.json`.
- `convergence validate`: schema and host checks (paths exist, symlink targets, syscall names
  against libseccomp), plus warnings for risky grants: the whole filesystem, home and
  credential directories, `/proc`, `/sys`, `/dev`, system directories, `any` ports,
  `unix_sockets: allow`, and secret-looking environment variables.
- `convergence explain --policy`: the status of every rule on this kernel (`enforced`,
  `enforced-with-caveat`, `partial`, `unenforceable`, `skipped`), using `doctor`'s live
  probes, or a hypothetical ABI with `--assume-abi`. Exits 3 when a rule is not fully
  enforceable, which `run` will refuse without `--allow-degraded`. Baseline gaps are reported
  on every kernel: signal scoping before ABI 6, and metadata operations (stat, chmod, chown,
  setxattr, utime) that Landlock never controls.
- The built-in syscall deny list and argument rules as data (`policy/baseline.py`),
  documented in `docs/policy.md` and checked against it by a test.
- `schemas/doctor-v1.json`, generated with the policy schema by `python -m convergence.schemas`;
  a test fails if either drifts.
- `docs/policy.md`, ADR 0004, and example policies in `examples/policies/`.
- Doctor evidence from every CI kernel (`docs/evidence/doctor/ci-*.json`), and the "Kernels
  tested" table in `docs/landlock-abi.md` filled from it.
- Dependencies: pydantic and PyYAML, resolved with a 14-day release cooldown
  (`exclude-newer = "14 days"`).
- `convergence doctor` (text and `--json`, schema `convergence.doctor/1`): reports the
  kernel, LSMs, Landlock ABI and errata, libseccomp, strace, and the calling process's
  privileges and seccomp state. It proves each feature with a live probe in a throwaway
  forked child, using a positive control, a denial, and where possible an external check.
  Probed live: Landlock filesystem rights, `REFER`, `TRUNCATE`, TCP ports, `IOCTL_DEV`,
  signal and abstract-unix scoping; seccomp argument filtering; `no_new_privs`;
  `RLIMIT_FSIZE`; ptrace through strace. Landlock features with no live probe yet (ABI 9-12)
  are reported as `abi-only`, never as verified. Exits 1 if the minimum enforcement set
  (filesystem Landlock, seccomp, `no_new_privs`, rlimits) is unavailable. The calling
  process is never confined.
- ctypes bindings: Landlock (`kernel/landlock.py`: ABI and errata queries, rulesets, path
  and port rules, `restrict_self`, a per-ABI feature table for ABI 1-12) and libseccomp
  (`kernel/seccomp.py`: build a filter, export classic BPF, install it with `prctl`).
- `docs/landlock-abi.md`: what each Landlock ABI adds, the structure layouts, and the errata,
  sourced from kernel `v7.4-rc2`. ADR 0002 (enforcement libraries) and ADR 0003 (ABI
  handling and test kernels).
- `docs/evidence/doctor/`: `doctor` output from the Ubuntu 24.04 GA-kernel VM (ABI 4).
- Tests: the ABI table, structure encodings, and protection logic for every ABI level;
  live kernel tests for the bindings, the forked-child runner, and `doctor` end to end.
- CI: an explicit `ubuntu-24.04` x86_64 job, `doctor` reports uploaded as artifacts, and a
  job that boots the stock Ubuntu 24.04 kernel in a nested QEMU/KVM VM through Lima.
  `scripts/vm.sh` can drive a VM on Linux (`CONVERGENCE_USE_VM=1`) and no longer downloads
  containerd for new VMs.
- Phase plan (`PLAN.md`) with the verified development environment and exit gates.
- Project skeleton: `convergence-sandbox` distribution (src layout, `uv_build`), the
  `convergence` command with `--version`, and `python -m convergence`. The CLI states that
  no enforcement is implemented yet.
- Tooling: ruff (lint and format), mypy in strict mode, pytest with `kernel`, `escape`,
  `holdout`, and `slow` markers, and a locked dependency set (`uv.lock`).
- `scripts/vm.sh`: creates and drives an Ubuntu 24.04 Lima VM on macOS, and runs the same
  commands directly on Linux. `scripts/provision.sh` installs uv 0.13.6, verified against
  SHA-256 checksums pinned in the script.
- `scripts/kernel-facts.sh`: prints kernel facts that matter for sandboxing (kernel, LSMs,
  Landlock ABI, seccomp state, strace, libseccomp, and the Yama and user-namespace sysctls).
  It is informational and is not the capability probe.
- GitHub Actions CI: lint, format, and type check, plus tests on `ubuntu-latest` (x86_64)
  and `ubuntu-24.04-arm` (arm64) for Python 3.12 and 3.13. Actions are pinned by commit
  SHA, and each test job prints the runner's kernel facts.
- ADR template and ADR 0001 (Python on kernel primitives, tested on real kernels).
