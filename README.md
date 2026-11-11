# Convergence

Convergence runs AI agent tools (MCP servers, agent skills, and model-generated scripts)
under a least-privilege policy that the Linux kernel enforces. It uses Landlock, seccomp-bpf,
and resource limits, and needs no root. It can also generate that policy from the tool's
observed behaviour, the way SELinux's `audit2allow` does.

It is the companion to [Divergence](https://github.com/vignesh-chaturvedi/divergence).
Divergence reports the gap between what an MCP server declares and what it actually does.
Convergence contains what it does.

## Status: pre-alpha, nothing is enforced yet

This repository is being built in phases; see [PLAN.md](PLAN.md). The current code is a
project skeleton. **It does not sandbox anything.** Do not use it to run untrusted code.

This README will only claim what the tests and benchmarks in this repository support. The
sections on what is enforced, the escape matrix, and the benchmarks will be added as the
phases that produce that evidence land.

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
