# ADR 0011 — Benchmark method: what is measured, and what "cold" means

**Status:** accepted · **Phase:** 7 · **Date:** 2026-11-12

## Context

Phase 7 compares the cost of starting a tool under Convergence with no sandbox, `bwrap`, and
Docker. The numbers are published whatever they are, so the method must be fixed before the
first run and stated with the results.

Checked in the development VM (Apple M2, Lima `vz`, Ubuntu 24.04.4, kernel 6.8, 4 CPUs,
2.9 GiB):
- `bwrap` 0.9.0 from Ubuntu **cannot run unprivileged on stock Ubuntu 24.04**: AppArmor
  restricts unprivileged user namespaces, and bwrap fails with "setting up uid map:
  Permission denied", with or without network isolation. It runs only if a profile grants
  it `userns`, which is a change to the host's security configuration. Convergence needs no
  namespaces.
- `docker.io` 29.1.3 is installed inside the VM (never Docker Desktop). The VM user is not
  in the `docker` group, which would be root-equivalent, so Docker runs through `sudo -n`.
  The cost of `sudo` itself is measured as its own row.

## Decision

**Configurations, all on one machine:**

| Name | What one run is |
|---|---|
| `bare` | `subprocess.run(argv)` from a warm Python process: no isolation at all |
| `sudo` | `sudo -n /usr/bin/true`: the overhead inside every Docker number |
| `convergence-api` | `convergence.api.Sandbox.run` in a warm process: a fork of the warm spawn helper (ADR 0010), sandbox setup, the tool |
| `convergence-api-trace` | the same with `trace=True` (strace attached, ADR 0007) |
| `convergence-mcp` | one `run_sandboxed` call in a warm MCP stdio session |
| `convergence-cli` | a fresh `convergence run` process: interpreter startup, imports, setup, the tool |
| `bwrap` | `bwrap` with `/usr` read-only, a private `/tmp` and `/proc`, the work directory bound, `--unshare-all --die-with-parent`, where bwrap can run |
| `docker-warm` | `sudo -n docker run --rm --network none` with the work directory mounted; daemon running, image present |
| `docker-cold` | the same, timed right after `systemctl restart docker` and a page-cache drop (`echo 3 > /proc/sys/vm/drop_caches`); the restart and drop are not timed |

**What "cold" and "warm" mean:**
- `convergence-cli` is cold in the *process* sense: a new interpreter every time, with the
  page cache warm, as when a user runs it repeatedly.
- `docker-cold` is cold in the *daemon and cache* sense, as the plan specifies.
- Everything else is warm: the measuring process, and the helper or daemon behind it, are
  already running.

**Workloads:**
- `true`: `/usr/bin/true`.
- `python`: `python3 -c pass`.
- `wordcount`: a Python script that counts the words of a 1 MiB file and writes the counts
  to a file.

Docker runs them in `python:3.12-slim`, pinned by the digest recorded in the results. The
host's Python and the image's Python may differ in patch version.

**Measurement:**
- At least 200 measured runs per configuration and workload, after 10 unmeasured warm-up
  runs (none for `docker-cold`).
- Wall-clock time of one run, measured with `time.perf_counter` around the call.
- Reported: p50, p95, p99 (nearest rank), mean, and standard deviation.

**Recorded:** CPU, cores, memory, kernel, OS, Python, and the version of every tool (strace,
bwrap, Docker, image digest).

**Output:**
- The JSON is authoritative, and the Markdown is generated from it.
- The README table is generated from the development VM's JSON, between markers, and a test
  fails if they drift.
- One command (`benchmarks/bench.py`) regenerates a result.
- CI x86_64 results are labelled as coming from a noisy shared runner.

## Consequences

- The comparison is honest about what each line includes. `docker-*` includes `sudo`
  (measured separately). `convergence-cli` includes starting Python. `bare` isolates
  nothing.
- A configuration that cannot run on a host is reported as unavailable, with the reason. It
  is not dropped or simulated.
- `docker-cold` runs restart the daemon, so they take minutes; that is the cost of
  measuring them.
