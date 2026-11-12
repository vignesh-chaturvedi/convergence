# Convergence

Convergence runs AI agent tools (MCP servers, agent skills, and model-generated scripts)
under a least-privilege policy that the Linux kernel enforces. It uses Landlock, seccomp-bpf,
and resource limits, and needs no root. It can also generate that policy from the tool's
observed behaviour, the way SELinux's `audit2allow` does.

It is the companion to [Divergence](https://github.com/vignesh-chaturvedi/divergence).
Divergence reports the gap between what an MCP server declares and what it actually does.
Convergence contains what it does.

## Status: pre-alpha

This repository is being built in phases; see [PLAN.md](PLAN.md). `convergence run`
enforces policies, but nothing here has been independently audited yet. Do not rely on it as
your only protection for untrusted code.

This README only claims what the tests and the escape matrix in this repository support.
Benchmarks will be added as the phases that produce them land.

## Run a tool under a policy: `convergence run`

```bash
convergence run --policy policy.yaml -- python3 tool.py --input data.json
```

The tool runs with:
- **Landlock** limiting it to the policy's files and TCP/UDP ports;
- **seccomp-bpf** denying escape-prone system calls, and socket families and protocols the
  policy does not grant;
- **`no_new_privs`** and resource limits;
- an environment built only from the policy, and no inherited descriptors beyond stdio.

Everything it starts is killed when its first process exits, or at the policy's wall-clock
limit. Convergence refuses a policy the running kernel cannot fully enforce, unless you pass
`--allow-degraded`, and then it lists exactly what is degraded. Each run is recorded as JSON
under `~/.local/state/convergence/runs/`, or printed with `--json`. With `--trace`, the
record also says which rule denied each failed operation (strace, outside the sandbox;
[ADR 0007](docs/adr/0007-denial-capture.md)). The spawn model is in
[ADR 0006](docs/adr/0006-spawn-model.md).

On the stock Ubuntu 24.04 kernel (6.8, Landlock ABI 4), the escape matrix gives these
results ([report](escape/results/README.md)):

| | Result |
|---|---|
| Development attacks blocked | 53 of the 55 that can be tested there (54 on the Linux 7.0 CI kernels) |
| Benign control workloads | all 10 run, with no false denials |
| Escapes | 1, running a readable program through the dynamic loader: a known limitation of the design, see [THREAT_MODEL.md](THREAT_MODEL.md) |
| Needs a newer kernel | 1, signal scoping (Landlock ABI 6) |

The sealed holdout, which was written independently of the runtime, has not been run yet.

## What works today: `convergence doctor`

`doctor` reports what the running kernel can enforce. It proves each feature by using it in
a throwaway child process: for example, a child confined by Landlock must be denied a read
outside its directory. A kernel version number alone is never taken as proof.

```bash
convergence doctor          # human-readable report
convergence doctor --json   # schema convergence.doctor/1
```

On the stock Ubuntu 24.04 kernel (6.8, Landlock ABI 4), `doctor` verifies filesystem access
control, cross-directory renames, truncation, TCP ports, seccomp argument filtering,
`no_new_privs`, the file-size resource limit, and ptrace tracing through strace. It also
reports what that kernel *cannot* do. For example, signal and abstract-unix-socket scoping need Landlock ABI 6
([sample output](docs/evidence/doctor/lima-ubuntu-24.04-ga-aarch64.txt),
[ABI reference](docs/landlock-abi.md)).

## Policies: `validate` and `explain`

A policy lists what a tool may do. Everything else is denied
([format reference](docs/policy.md), [examples](examples/policies/)).

```bash
convergence validate policy.yaml          # schema, paths, syscall names, risky grants
convergence explain --policy policy.yaml  # how each rule is enforced on this kernel
```

`explain` reports every rule as `enforced`, `enforced-with-caveat`, `partial`, or
`unenforceable` on the running kernel. `run` refuses a policy with a `partial` or
`unenforceable` rule unless told explicitly. For example, on stock Ubuntu 24.04
(Landlock ABI 4), limiting UDP to port 53 is `unenforceable`: that needs ABI 10.

Landlock filters network access by **port, not host**. Allowlisting hosts or IP addresses is
out of scope for v1.

## Development

Enforcement is Linux-only, and every security test runs against a real kernel. On macOS,
development uses a [Lima](https://lima-vm.io) VM running Ubuntu 24.04. Docker Desktop is not
used, because its VM kernel and default seccomp profile can hide or block the primitives
under test ([ADR 0001](docs/adr/0001-python-on-kernel-primitives-tested-on-real-kernels.md)).

```bash
scripts/vm.sh create      # macOS only: create and start the VM
scripts/vm.sh provision   # install the pinned toolchain (uv) inside Linux
scripts/vm.sh check       # lint, format check, type check, and tests inside Linux
```

On a Linux machine, the same `scripts/vm.sh` commands run directly on the host.

## License

[Apache License 2.0](LICENSE).
