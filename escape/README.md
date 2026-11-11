# Escape matrix — implementation specification

This directory is the escape matrix: a corpus of attack cases and benign controls that
measure whether Convergence's enforcement holds, on a real kernel, with no mocks. This
README is the **specification to implement against**. The decisions behind it are in
[ADR 0005](../docs/adr/0005-escape-matrix-design.md); the boundary it tests is in
[THREAT_MODEL.md](../THREAT_MODEL.md).

> **State at handoff (Phase 3):** this is a design document. The case files, oracles, and
> runner are to be implemented next. Where this spec says "the runner does X", it means the
> runner *must* do X once written. Nothing here mocks kernel behaviour.

## Principles (do not weaken these)

1. **External oracles only.** A case's verdict comes from ground truth the harness controls,
   never from what the payload prints about itself. See [Oracles](#oracles).
2. **Validity first.** Every attack must be shown to *escape when unconfined* before it
   counts. An attack that cannot escape unconfined is invalid and is rewritten.
3. **Real kernels only.** Cases run under the Lima VM and in CI, including the nested
   stock-24.04 VM. No mock ever stands in for Landlock, seccomp, or rlimits.
4. **ABI-aware.** A case names the mechanism and minimum ABI expected to stop it. Below that
   ABI, an escape is a *documented limitation*, not a failure.
5. **The holdout is sealed and not consulted during Phase 4 tuning.**

## Layout

```
escape/
  README.md                 # this spec
  schema.py                 # CaseSpec model + loader (strict, like policy/model.py)
  runner.py                 # loads cases, launches payloads, applies oracles, scores
  launchers.py              # UnconfinedLauncher (now) and ConvergenceLauncher (Phase 4)
  oracles/                  # one module per oracle type; a small registry
  cases/
    dev/*.yaml              # development attacks (>= 45)
    holdout/*.yaml          # holdout attacks (>= 20)
    holdout.sha256          # sealed manifest of the holdout files (committed Phase 3)
  holdout-runs.log          # appended to on every holdout run (created on first run)
controls/*.yaml             # benign controls (>= 10), same case schema, verdict: allowed
```

Payload code may be inlined in a case (`payload.argv` running `python3 -c "..."`) or kept in
a sibling file referenced by `payload.file`. Keep payloads small and single-purpose.

## Case schema (`convergence.escapecase/1`)

Strict, like the policy loader: unknown keys are errors, no coercion. Implement in
`schema.py` with the same approach as `convergence/policy/model.py`.

```yaml
id: fs-read-secret-001           # unique, kebab-case, <category>-<slug>-<nnn>
category: filesystem-read        # from the category list below
description: >
  Reads a secret file the policy does not grant and copies it to an allowed output.
expect:
  verdict: blocked               # blocked | allowed  (controls use allowed)
  mechanism: landlock-fs         # informational: expected stopping mechanism
  min_abi: 1                     # Landlock ABI the mechanism needs; 0 = none (seccomp/rlimit/supervisor)
  # Optional. If set, the attack is only expected to be blocked at abi >= min_abi.
  # Below it the runner records "documented-limitation", not a failure. Omit (or 0)
  # for attacks that must be blocked on every supported kernel.
policy:                          # inline convergence.policy/1; ${VARS} expanded by the runner
  version: 1
  filesystem:
    read: [/usr, /etc/ld.so.cache, "${WORKDIR}"]
    write: ["${OUT_DIR}"]
    execute: ["${PYTHON}", {path: "${LOADER}", optional: true}]
  environment:
    set: {PATH: /usr/bin:/bin}
payload:
  argv: ["${PYTHON}", "-c", "import pathlib,sys; sys.stdout.write(open('${CANARY_FILE}').read())"]
  # or:  file: payloads/fs_read_secret.py   (resolved relative to the case file)
  # stdin: optional string piped to the payload
oracle:
  type: canary-file-read         # see the oracle table
  nonce: secret                  # which planted nonce the payload tries to exfiltrate
platforms:
  arch: [x86_64, aarch64]        # default: both
```

### Runner-provided substitution variables

The runner creates fresh per-case state and expands these in `policy` and `payload` (string
substitution on the raw YAML text before policy parsing). Attacks never receive the value of
a nonce they are supposed to be unable to read — only its *path* or its *destination*.

| Variable | Meaning |
|---|---|
| `${WORKDIR}` | fresh per-case directory; the payload's cwd; granted as the case chooses |
| `${OUT_DIR}` / `${OUT}` | a granted-writable directory / a file in it; the harness scans everything written here for nonces |
| `${SCRATCH}` | passed through to the policy's `${SCRATCH}` |
| `${PYTHON}` | absolute path to the interpreter (resolved once, e.g. `/usr/bin/python3.12`) |
| `${LOADER}` | absolute path to `ld-linux-*.so` for this arch (optional in policies) |
| `${CANARY_FILE}` | absolute path to a secret file planted **outside** all grants |
| `${CANARY_DItoR}`… | (see oracle table for the full set, e.g. `${FORBIDDEN_PATH}`, `${SENTINEL_FILE}`) |
| `${SINK_HOST}` / `${SINK_PORT}` | address of the harness network sink |
| `${SENTINEL_PID}` | pid of the harness sentinel process |

Nonces themselves (`${CANARY_NONCE}` …) are **not** exposed to attack payloads; the harness
holds them and searches for them. A control may receive a nonce when its job is to move data
through an allowed channel.

## Oracles

Each oracle is "set up by the harness, checked by the harness". `escaped`/`contained` is the
attack verdict; `succeeded`/`failed` is the control verdict. Implement each as a module in
`oracles/` exposing `setup(ctx) -> state` and `check(ctx, state, run_result) -> Outcome`.

| `oracle.type` | Harness setup | Payload attempts | `escaped` (bad) when | `contained` (good) when |
|---|---|---|---|---|
| `canary-file-read` | plant secret file with random nonce outside all grants | read it, copy to `${OUT}`/stdout | the nonce appears in any scanned output channel | the nonce never appears |
| `canary-file-write` | note `${FORBIDDEN_PATH}` outside write grants (may pre-exist with known content) | create/modify it | host sees the file created or its content changed | path unchanged / not created |
| `canary-delete` | plant a sentinel file outside write grants | unlink/rename it | host sees it gone or moved | still present, unchanged |
| `network-sink` | bind a harness listener on `${SINK_PORT}` (TCP or UDP) **not** in the policy, expecting a nonce | connect/send the nonce | the sink received a connection or the nonce | sink saw nothing within the deadline |
| `process-read` | start a sentinel holding a nonce in memory; pass `${SENTINEL_PID}` | `ptrace`/`process_vm_readv`/`/proc/pid/mem` the nonce, copy to `${OUT}` | the nonce appears in output | it never appears |
| `process-signal` | start a sentinel that writes a nonce to a host file on `SIGUSR1`; pass its pid | signal it | the host file gains the nonce | file never written |
| `env-leak` | place `${CANARY_NONCE}` in the **supervisor's** environment, not passed by policy | read own `environ`, copy to `${OUT}` | the nonce appears in output | it never appears |
| `fd-leak` | open a file holding a nonce before launch (a descriptor that must be closed) | read fds 3..N, copy to `${OUT}` | the nonce appears in output | it never appears |
| `resource-dos` | record baseline (process count, time, memory) | fork bomb / allocate / spin / grow a file / open fds | host observes the DoS effect past limits (see note) | the limit or deadline held; no leaked/surviving process |
| `persist` | become subreaper-aware; record the process group | `setsid` or double-fork a daemon that outlives the tool | a descendant is still alive after the deadline + grace | process group fully reaped |
| `exec-probe` | plant a marker binary/script the payload tries to run | exec it directly, via interpreter, via `${LOADER}` | the marker ran (host-observable side effect, e.g. a file it writes) | it did not run |

Notes:
- **Output channels scanned for a nonce:** the payload's captured stdout and stderr, and every
  file under `${OUT_DIR}`. These are the only channels an attack is given; the point of a
  blocked read is that the nonce never reaches any of them.
- **`resource-dos` thresholds** are measured, not claimed: elapsed wall-clock vs the policy
  deadline plus a fixed grace; peak RSS vs the memory limit; a written file's size vs the
  file-size limit; the host process-group being empty after the run. Define the grace and the
  thresholds once in `runner.py` and document them in the result.
- A `network-sink` **control** uses a port the policy *grants*; its success condition is that
  the sink *did* receive the nonce.

## Launchers

`launchers.py` defines a common interface: given a parsed policy, an argv, an environment, a
workdir, and a deadline, run the payload and return `RunResult` (exit status, captured stdout
and stderr with byte caps and truncation flags, elapsed time, and — for the convergence
launcher — the run record with denials).

- `UnconfinedLauncher`: a bare `subprocess` in the workdir with the policy's environment, no
  enforcement. Available now. Used for the validity gate and for `--unconfined` runs.
- `ConvergenceLauncher`: invokes `convergence run --policy <generated> -- <argv>` (Phase 4).
  Until Phase 4 exists it must raise a clear "not implemented" error, so the confined matrix
  is explicitly red rather than silently passing.

The runner writes the case's expanded policy to a temp file and hands it to the launcher.

## Runner and verdict logic

`runner.py` responsibilities:

1. Load and validate every case (strict schema). Refuse duplicate ids.
2. Enforce the holdout seal and `--holdout-run` gate (below).
3. For each case: create fresh `${WORKDIR}`, `${OUT_DIR}`, canaries, sinks, sentinels;
   expand variables; write the policy; set up the oracle.
4. Launch the payload with the chosen launcher under the case's own deadline.
5. Run the oracle's `check`. Tear down all per-case state (kill the sentinel, close the sink,
   remove temp dirs, reap the process group).
6. Score.

Scoring, per case:

| Case kind | Launcher | Oracle outcome | Result |
|---|---|---|---|
| attack (no `min_abi`, or kernel ABI ≥ `min_abi`) | convergence | contained | **pass** |
| attack | convergence | escaped | **escape** (fail: policy too loose) |
| attack (kernel ABI < `min_abi`) | convergence | escaped | **documented-limitation** (expected) |
| attack (kernel ABI < `min_abi`) | convergence | contained | **pass** (better than required; note it) |
| attack | unconfined | escaped | **valid** (required) |
| attack | unconfined | contained | **invalid case** (fail: proves nothing) |
| control | convergence | succeeded | **pass** |
| control | convergence | failed | **false-denial** (fail: policy too tight) |
| control | unconfined | succeeded | **valid** |
| control | unconfined | failed | **invalid control** |

A case whose policy is `unenforceable` on the running kernel (from `convergence explain`)
is reported as `skipped-unenforceable` under the convergence launcher, with the reason — it
is neither an escape nor a pass. Prefer policies that are enforceable on the target kernels;
where a category inherently needs a higher ABI, use `min_abi`.

### Metrics

- **escape rate** = escapes / (attacks counted on this kernel), excluding
  documented-limitation and skipped-unenforceable, with a Wilson 95% interval.
- **false-denial rate** = failed controls / controls, with a Wilson 95% interval.
- Reported per kernel (ABI 4 GA, ABI 8 CI, …) and split dev vs holdout. Documented
  limitations are listed explicitly, never folded into the escape rate.

### Runner CLI (target)

```
python -m escape.runner run --set dev --launcher unconfined   # validity gate (Phase 3)
python -m escape.runner run --set dev --launcher convergence   # the matrix (Phase 4)
python -m escape.runner run --set holdout --launcher convergence --holdout-run
python -m escape.runner validity                               # all attacks must escape unconfined
python -m escape.runner report --json out/escape.json --markdown out/escape.md
```

Exit non-zero if any attack escapes (convergence launcher), any control is falsely denied,
or any case fails the validity gate.

## Holdout seal

- `escape/cases/holdout.sha256`: one `sha256  path` line per file under `cases/holdout/`
  (cases and any payload files), sorted by path, followed by a final line with the SHA-256 of
  that manifest text. Generated by a helper (`python -m escape.runner seal-holdout`) and
  committed in Phase 3.
- A pytest (`tests/test_escape_holdout.py`) recomputes the digests and fails on any
  mismatch, so the holdout cannot be edited unnoticed.
- The runner refuses `--set holdout` without `--holdout-run`, and on a holdout run appends one
  line to `escape/holdout-runs.log`: ISO timestamp, `git rev-parse HEAD`, kernel release,
  Landlock ABI, arch, and the result summary (counts + escape rate).
- **Discipline:** do not open the holdout cases while implementing or tuning Phase 4. The
  holdout is run once per milestone and the result reported as-is.

## Category coverage checklist

Implement at least the counts below (dev / holdout), each with the oracle and expected
mechanism shown. `min_abi` marks where a lower kernel yields a documented limitation.

| Category | Oracle | Mechanism | `min_abi` | dev | holdout |
|---|---|---|---:|---:|---:|
| filesystem-read (outside grants) | canary-file-read | landlock-fs | 1 | 3 | 2 |
| filesystem-write (outside grants) | canary-file-write | landlock-fs | 1 | 3 | 1 |
| filesystem-delete | canary-delete | landlock-fs | 1 | 2 | 1 |
| traversal-symlink | canary-file-read | landlock-fs | 1 | 2 | 1 |
| traversal-hardlink | canary-file-read | landlock-fs | 1 | 1 | 1 |
| traversal-dotdot | canary-file-read | landlock-fs | 1 | 1 | 1 |
| traversal-rename-refer | canary-file-write | landlock-fs | 1 | 1 | 1 |
| proc-self | canary-file-read / process-read | landlock-fs | 1 | 3 | 1 |
| proc-other-pid | process-read | landlock-fs + ptrace-domain | 1 | 2 | 1 |
| exec-disallowed (direct) | exec-probe | landlock-fs | 1 | 2 | 1 |
| exec-via-interpreter | exec-probe | landlock-fs | 1 | 1 | 1 |
| exec-via-loader | exec-probe | landlock-fs (measured) | 1 | 1 | 1 |
| setuid-no-new-privs | exec-probe | no_new_privs | 0 | 1 | 1 |
| net-tcp-connect | network-sink | landlock-net | 4 | 2 | 1 |
| net-tcp-bind | network-sink | landlock-net | 4 | 1 | 1 |
| net-udp | network-sink | seccomp (proto) / landlock-net | 0/10 | 1 | 1 |
| net-raw-socket | network-sink | seccomp | 0 | 1 | 0 |
| unix-socket-host | network-sink | landlock (ABI 9) / seccomp | 0 | 1 | 1 |
| ptrace | process-read | seccomp | 0 | 1 | 1 |
| process-vm-readv | process-read | seccomp | 0 | 1 | 0 |
| mount-namespace (mount/unshare/setns/clone-ns) | canary-file-read / persist | seccomp | 0 | 3 | 1 |
| clone3-bypass | canary-file-read | seccomp (ENOSYS fallback) | 0 | 1 | 1 |
| io-uring-bypass | canary-file-read / canary-file-write | seccomp | 0 | 1 | 1 |
| bpf-perf-keyctl-userfaultfd | process-read / resource-dos | seccomp | 0 | 1 | 0 |
| tiocsti-injection | process-signal (proxy) | seccomp (ioctl arg) | 0 | 1 | 0 |
| signal-outside | process-signal | landlock-signal-scope | 6 | 1 | 1 |
| resource-fork-bomb | resource-dos | rlimit + supervisor | 0 | 1 | 1 |
| resource-memory | resource-dos | rlimit | 0 | 1 | 0 |
| resource-cpu | resource-dos | rlimit + supervisor | 0 | 1 | 0 |
| resource-file-size | resource-dos | rlimit | 0 | 1 | 0 |
| resource-fd-exhaustion | resource-dos | rlimit | 0 | 1 | 0 |
| persist-setsid-doublefork | persist | supervisor | 0 | 2 | 1 |
| env-leak | env-leak | supervisor | 0 | 1 | 1 |
| fd-leak | fd-leak | supervisor | 0 | 1 | 0 |

Totals meet the ≥45 dev / ≥20 holdout targets with margin. Adjust counts up, not down;
keep each category represented in both sets.

## Benign controls (≥ 10)

Same schema, `expect.verdict: allowed`, each with the tightest policy that still lets it
work, and a positive oracle (the work's real effect, checked by the harness).

1. Python stdlib script reading `${WORKDIR}` and writing `${OUT}` (offline).
2. `git status` + `git log` on a fixture repo under `${WORKDIR}`.
3. Shell pipeline: `grep`/`find`/`sed` over `${WORKDIR}`.
4. `tar` + `gzip` of `${WORKDIR}` into `${OUT}`.
5. Python `sqlite3`: create a DB in `${OUT}`, insert, query.
6. HTTP client to the harness sink on an **allowed** port (oracle: sink received the request).
7. A server that binds an **allowed** port and answers one request.
8. A real stdio MCP server built with the `mcp` SDK, answering one `tools/call`.
9. `python3 -m json.tool` reading `${WORKDIR}`, writing `${OUT}`.
10. A build-like task (`make` or a compile) confined to `${WORKDIR}` and `${SCRATCH}`.

Controls are where the **false-denial rate** is measured, and where the Phase 4 decision on
mitigating metadata writes (`chmod`/`chown`/`utime`) will be judged: several of these
(`tar`, `git`, `make`) legitimately touch file metadata.

## What Phase 3 commits vs Phase 4

- **Phase 3 (this handoff → next author):** `schema.py`, `runner.py`, `launchers.py`,
  `oracles/`, all dev and holdout cases, the controls, the sealed `holdout.sha256`, the
  committed **unconfined validity** results (every attack escapes, every control succeeds),
  and the committed **initially-red** confined baseline (every attack escapes because
  `convergence run` does not exist yet). The CI escape job is added and allowed to fail.
- **Phase 4:** build `convergence run`, make `ConvergenceLauncher` real, drive the
  development escape rate to zero (or document each exception here and in THREAT_MODEL.md),
  then run the holdout **once** and commit the result as-is.
