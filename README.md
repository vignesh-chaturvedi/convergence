# Convergence

Convergence runs AI agent tools (MCP servers, agent skills, model-generated scripts) under a
least-privilege policy that the Linux kernel enforces. It uses Landlock, seccomp-bpf,
`no_new_privs`, and resource limits, needs no root and no namespaces, and runs on a stock
Ubuntu 24.04 kernel.

It can also write the policy for you from what a tool actually did, the way SELinux's
`audit2allow` does. Every rule says which observed event justified it.

It is the companion to [Divergence](https://github.com/vignesh-chaturvedi/divergence).
Divergence reports the gap between what an MCP server declares and what it does;
Convergence contains what it does.

> **Status: 0.1.1.** Every claim below comes from tests and measurements in this
> repository, on real kernels. A [security review](docs/security-review.md) found seven
> weaknesses in 0.1.0. All are fixed in 0.1.1, so do not use 0.1.0. Nothing here has been
> independently audited. Do not make it your only protection for code you do not trust.

## Quickstart

```bash
pip install convergence-sandbox            # add [mcp] for the MCP server
convergence doctor                         # what this kernel can enforce, proven live
```

A policy lists what a tool may do; everything else is denied
([reference](docs/policy.md), [examples](examples/policies/)):

```yaml
version: 1
filesystem:
  read: [/usr, /etc/ld.so.cache, "${CWD}"]
  write: ["${SCRATCH}"]
  execute: [/usr/bin/python3.12, /lib64/ld-linux-x86-64.so.2]
network: {tcp_connect: [443]}
resources: {wall_clock_seconds: 60}
environment: {set: {PATH: /usr/bin, HOME: "${SCRATCH}"}}
```

```bash
convergence explain --policy policy.yaml             # how this kernel enforces each rule
convergence run --policy policy.yaml -- python3 tool.py
```

Or let Convergence write the policy:

```bash
convergence observe --out obs.json -- python3 tool.py    # NOT a sandbox: use a disposable VM
convergence generate --from obs.json --out policy.yaml
convergence run --trace --policy policy.yaml -- python3 tool.py
convergence explain --run <run id>                        # why something was denied, and the fix
```

## What is enforced

| Mechanism | What it does |
|---|---|
| **Landlock** | Files: read, write, and execute only where granted. TCP ports from ABI 4, UDP from ABI 10, signals and abstract unix sockets scoped to the sandbox from ABI 6 |
| **seccomp-bpf** | Denies escape- and tamper-prone syscalls: `ptrace`, `process_vm_*`, `mount`, `unshare`, namespace flags on `clone`, `io_uring`, `bpf`, `perf_event_open`, `userfaultfd`, keyrings, `TIOCSTI`, and more. Allows only the socket families, types, and protocols the policy grants. Denies TCP fast open, which would pass Landlock's port rules, and `prlimit64` on other processes. Not user notification, which is never used as a boundary |
| **`no_new_privs`** | setuid and file-capability binaries gain nothing |
| **rlimits** | CPU, memory, file size, open files, processes; core dumps off |
| **The supervisor** | Builds the environment from the policy alone and closes inherited descriptors. When the tool's first process exits, or at the wall clock, it kills everything the tool started, including daemons that left the session |

Convergence refuses a policy the running kernel cannot fully enforce, unless you pass
`--allow-degraded`, and then it lists exactly what is degraded. Each run leaves a JSON
record. Design: [THREAT_MODEL.md](THREAT_MODEL.md) and the [ADRs](docs/adr/).

## What is not enforced

These are documented, measured where possible, and not hidden:

- **Hosts.** Landlock filters by port, not host: `tcp_connect: [443]` allows HTTPS to every
  host.
- **Code the tool can read.** Execute grants limit which files the kernel starts. They do
  not stop the dynamic loader running a file the tool can only read, or the tool running
  code it has put in memory. This is the one escape the matrix found, in development and in
  the holdout; whatever runs that way stays inside the sandbox.
- **Older kernels.** Below Landlock ABI 6, the tool can signal other processes of the same
  user. That includes Convergence's own supervisor: stopping it defeats the time limit and
  the clean-up. Below ABI 9, unix sockets cannot be limited to the sandbox, so they are
  denied altogether.
- **Listening.** `tcp_bind` limits explicit binds. Where `listen` has to stay allowed, the
  tool can accept TCP connections on a port the kernel picks.
- **File metadata and scheduling.** `stat`, `chmod`, `chown`, and `utime` are outside
  Landlock's control. The tool can also change the priority and CPU affinity of your other
  processes.
- **A tool that keeps forking, without a process limit.** The final clean-up is only
  certain while `resources.max_processes` is set (the default).
- **A supervisor killed with `SIGKILL`.** The tool dies with it, but processes it started
  can outlive it.
- **Kernel exploits, side channels, and misuse of what the policy grants.**
- **`observe` and `--trace`** run strace with your access. `observe` is not a sandbox at
  all.

## Results

All measured on real kernels, with no mocks. Rates carry Wilson 95% intervals.

**The escape matrix** ([report](escape/results/README.md)). Attacks are judged by external
oracles: canary files, network sinks, sentinel processes, the process table. Every attack is
first proven to escape with no sandbox.

| Set | Kernel | Escape rate | Other outcomes |
|---|---|---|---|
| 47 development attacks | stock Ubuntu 24.04, 6.8 (ABI 4) | 1/44 (2.3%; 0.4–11.8%) | 1 needs ABI 6; 2 not testable on that host |
| 47 development attacks | Linux 7.0 (ABI 8), 3 CI runners | 1/45 (2.2%; 0.4–11.6%) | 2 not testable |
| **26 holdout attacks**, sealed, written independently, run once | stock Ubuntu 24.04, 6.8 | **1/22 (4.5%; 0.8–21.8%)** | 1 needs ABI 6; 3 proved nothing either way |

Every escape is the dynamic-loader limitation above.

**What the matrix missed.** A [security review](docs/security-review.md) after 0.1.0 found
seven weaknesses that no matrix case covered. The most serious let a tool reach TCP ports
the policy did not grant, and outlive the wall-clock limit by forking. All seven are fixed
in 0.1.1 and have regression tests. None has a matrix case yet, so the rates above do not
count them.

**False denials**, on 10 benign workloads: git, tar, sqlite, an HTTP client and server,
shell pipelines, and more.

| Policy | False-denial rate |
|---|---|
| Hand-written | 0/10 (0.0%; 0.0–27.8%) |
| Generated from one observation, same input | 0/10 (0.0%; 0.0–27.8%) |
| Generated from one observation, different input | 3/10 (30%; 10.8–60.3%) |

The last row is how incomplete a single observation is. Observe a tool on the inputs it will
really get.

## What it costs

<!-- benchmarks:start -->
Generated from [`benchmarks/results/lima-ubuntu-24.04-ga-aarch64.json`](benchmarks/results/lima-ubuntu-24.04-ga-aarch64.json) by `benchmarks/bench.py`: development VM (Apple M2, Lima vz), 4 CPUs, kernel 6.8.0-134-generic (aarch64). Wall-clock time to start the workload and see it exit; p50 (p95) in milliseconds over 200 runs.

| Configuration | `true` p50 (p95) ms | `python` p50 (p95) ms | `wordcount` p50 (p95) ms |
|---|---:|---:|---:|
| no sandbox (`subprocess`) | 0.21 (0.27) | 7.72 (8.91) | 16.65 (18.48) |
| `sudo -n true` (inside every Docker row) | 2.64 (3.74) | 2.6 (3.19) | 2.66 (3.84) |
| Convergence, library API, warm | 7.89 (10.62) | 16.41 (21.06) | 26.83 (32.78) |
| Convergence, library API, warm, `--trace` | 23.09 (26.58) | 67.03 (74.55) | 82.47 (92.23) |
| Convergence, one MCP `run_sandboxed` call | 8.64 (11.03) | 16.84 (20.41) | 26.6 (34.02) |
| Convergence CLI, cold process | 114.37 (127.58) | 122.65 (135.06) | 132.79 (147.29) |
| bubblewrap | n/a | n/a | n/a |
| `docker run --rm`, warm | 106.64 (139.13) | 116.17 (139.36) | 138.15 (171.59) |
| `docker run --rm`, cold daemon and cache | 151.08 (200.74) | 161.39 (193.82) | 195.47 (348.86) |

n/a: bwrap cannot run here: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
<!-- benchmarks:end -->

- **What the rows include.** Each Docker row includes `sudo`, which has its own row. The
  cold CLI row includes starting Python.
- **A warm call**, through the library API or MCP, costs one fork and the sandbox setup.
- **bubblewrap** cannot run unprivileged on stock Ubuntu 24.04, on the VM or on GitHub's
  runner: AppArmor restricts the user namespaces it needs.
- **Method:** [ADR 0011](docs/adr/0011-benchmark-method.md). An x86_64 run on a GitHub
  runner is in [benchmarks/](benchmarks/README.md).

## Commands

| Command | Does |
|---|---|
| `doctor` | Proves what this kernel can enforce, using each feature in a throwaway child |
| `validate POLICY` | Checks the schema, the paths, the syscall names, and risky grants |
| `explain --policy POLICY` | Shows how this kernel enforces each rule: `enforced`, `partial`, or `unenforceable` |
| `run --policy POLICY -- CMD` | Runs CMD sandboxed. `--trace` records which rule denied each failed operation |
| `observe -- CMD` | Records what CMD does under strace. **Not a sandbox** |
| `generate --from OBS` | Writes the smallest policy for an observation, with a reason per rule |
| `explain --run ID` | For each denial: the cause, the rule, the smallest fix as a YAML diff, and the risk |
| `import divergence REPORT` | Turns a Divergence dynamic-tier report into a partial observation |
| `mcp --policies DIR` | Serves `run_sandboxed`, `check_policy`, `generate_policy`, and `explain_denials` over MCP |

`run` exits with the tool's own status, or 128+N for signal N, 124 at the wall clock, 125
when the tool was not started, 126 when it could not execute, and 127 when it was not found.

### For agents: `convergence mcp`

```bash
pip install 'convergence-sandbox[mcp]'
convergence mcp --policies ./policies
```

- **The operator chooses the policies, not the agent.** A client can only name a policy in
  `--policies`, unless the server is started with `--allow-inline-policy`.
- **Commands are argv lists**, never shell strings.
- **`observe`**, which runs commands unconfined, exists only with `--allow-observe`
  ([ADR 0010](docs/adr/0010-mcp-server.md)).

From Python, `convergence.api.Sandbox` runs commands through the same warm helper.

## Prior art

Checked against each project's own repository on 2026-11-12:

- **[sandlock](https://github.com/multikernel/sandlock)** (Apache-2.0) is the closest. It
  uses Landlock, seccomp-bpf, and seccomp user notification. It needs Linux 6.12 or later
  (Landlock ABI 6). It has `sandlock learn`, which turns observed behaviour into a profile,
  and an MCP integration. Convergence differs in four ways:
  - it runs on the stock 24.04 kernel (ABI 4);
  - it never relies on user notification for enforcement, because of time-of-check races on
    pointer arguments;
  - every generated rule cites the observations behind it;
  - it publishes an escape matrix with a sealed holdout.
- **[bubblewrap](https://github.com/containers/bubblewrap)** isolates with namespaces. It
  needs unprivileged user namespaces, which stock Ubuntu 24.04 restricts through AppArmor
  (measured above).
- **OpenAI [Codex CLI](https://github.com/openai/codex)** sandboxes commands with bubblewrap
  and seccomp on Linux, keeping a legacy Landlock path, and with Seatbelt on macOS. It warns
  when bubblewrap cannot create user namespaces.
- **Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)**
  is used by Claude Code and can also wrap MCP servers. It uses bubblewrap on Linux and
  `sandbox-exec` on macOS, with proxy-based network filtering.

## With Divergence

[Divergence](https://github.com/vignesh-chaturvedi/divergence) runs an MCP server or skill
inside its own sandbox and reports what it touched. `convergence import divergence` turns
that report into an observation, so a policy can be generated without ever running the tool
unconfined:

```bash
convergence observe --out runtime.json -- python3 -c pass      # the interpreter's own needs
convergence import divergence report.json --baseline runtime.json --out obs.json
convergence generate --from obs.json --out policy.yaml
```

- **Decoys, secrets, and blocked attempts** are never granted.
- **The import is always partial.** Divergence drops runtime noise on purpose, which is why
  the runtime baseline is merged in.

## Development

Enforcement is Linux-only, and every security test runs against a real kernel. On macOS,
development uses a [Lima](https://lima-vm.io) VM with Ubuntu 24.04, never Docker Desktop
([ADR 0001](docs/adr/0001-python-on-kernel-primitives-tested-on-real-kernels.md)). CI runs
everything on GitHub's x86_64 and arm64 runners, and on the stock 24.04 kernel in a nested
VM.

```bash
scripts/vm.sh create      # macOS only: create and start the VM
scripts/vm.sh provision   # install the pinned toolchain (uv) inside Linux
scripts/vm.sh check       # lint, format check, type check, and tests inside Linux
```

How the project was built, phase by phase: [PLAN.md](PLAN.md).
Changes: [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](LICENSE).
