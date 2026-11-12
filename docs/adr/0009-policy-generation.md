# ADR 0009 — Policy generation: exact grants, justified collapses, nothing secret

**Status:** accepted · **Phase:** 5 · **Date:** 2026-11-12

## Context

`convergence generate` turns an observation (ADR 0008) into a policy. A policy is only as
good as its smallest grant, so the generator has two jobs:
- grant what was observed, and no more;
- make every rule reviewable, which means saying why each rule exists.

## Decision

**Every rule cites the observation events that justify it.** The YAML carries a comment per
rule. `--rationale` writes the full mapping as JSON.

**Filesystem:**

| Observed | Grant |
|---|---|
| a file opened for reading | `read` on that file |
| a directory listed (`getdents`) | `read` on that directory |
| a file opened for writing, without `O_CREAT` | `write` on that file |
| a file opened with `O_CREAT`; a file created, removed, or renamed; a directory made or removed | `write` on the parent directory |
| a program executed | `execute` on it, plus its ELF interpreter (`PT_INTERP`) or `#!` interpreter |

- Paths are the real paths the kernel resolved, since Landlock rules attach to inodes.
- The pseudo-devices `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, and
  `/dev/urandom` are granted `write` even when only read. Before Landlock ABI 5 a read-only
  device grant cannot be enforced exactly, since ioctl is not controlled, and `run` refuses
  it. Every user may already write to these devices, and a write grant includes ioctl.
  (Found by the same-input false-denial measurement.)
- Paths under the working directory become `${CWD}/...`, and paths under the home directory
  `${HOME}/...`, so the policy works from another checkout.
- Failed opens grant nothing: a missing file needs no rule, and an `EACCES` from file
  permissions would not be fixed by one.
- Reading or changing metadata (`stat`, `access`, `chmod`) needs no grant; Landlock does
  not control it (THREAT_MODEL.md).

**Collapsing:**
- A runtime tree may be granted as one directory when at least 5 files were read under it.
  The rationale says how many ("212 files read under /usr/lib/python3.12").
- The candidates are fixed: the first directory level below `/usr/lib`, `/usr/lib64`,
  `/usr/share`, `/usr/local/lib`, `/lib`, `/lib64`, and `/opt`, and any `site-packages`,
  `dist-packages`, or `node_modules` directory.
- A collapse never lands on `/`, `/etc`, `/usr`, `$HOME`, or an ancestor of any of them, and
  never contains a credential location.

**Never granted, reported as warnings instead:**
- credential locations (the `validate` list: `~/.ssh`, `~/.aws`, ...);
- another process's `/proc/<pid>`;
- connections to unix sockets, which can reach host services.

From a Divergence report (later in Phase 5), decoys, `secrets_read`, and blocked attempts are
never granted either.

**Network:**
- Ports are granted for each connect, send, or bind observed. This includes connects the
  network refused, since the tool needed the port.
- A failed attempt that was denied (`EACCES`, `EPERM`) grants nothing.

**The rest:**
- **Syscalls:** deny-list mode by default. `--allow-list` emits the observed set, which is
  stricter and more fragile.
- **Resources:** the defaults, raised with headroom where the observation exceeded them.
- **Environment:** `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, and `TZ` are
  passed if the caller had them, because environment reads cannot be observed. The policy
  says so.

**Output:** the generated text must parse as a valid policy before it is written.

## Consequences

- A generated policy fails closed: a code path the observation did not take may be denied,
  and the run record shows where (`--trace`, `explain --run`).
- Collapsing trades exactness for robustness only inside installed software trees, never
  over user data.
- The rules are deterministic and testable: the same observation gives the same policy.
