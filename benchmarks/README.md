# Benchmarks

What it costs to start a tool under Convergence, compared with no sandbox, bubblewrap, and
Docker. The method is fixed in [ADR 0011](../docs/adr/0011-benchmark-method.md):
- which configurations are run, and what "cold" means;
- three workloads: `/usr/bin/true`, `python3 -c pass`, and a 1 MiB word count;
- at least 200 measured runs per cell.

| Result | Where |
|---|---|
| [`results/lima-ubuntu-24.04-ga-aarch64.md`](results/lima-ubuntu-24.04-ga-aarch64.md) | the development VM: Apple M2 under Lima (`vz`), Ubuntu 24.04, stock kernel 6.8. The README table is generated from its JSON. Measured on 0.1.1 while the host was busy with other work, so slower and with longer tails than the 0.1.0 run |
| [`results/gha-ubuntu-24.04-x86_64.md`](results/gha-ubuntu-24.04-x86_64.md) | a GitHub-hosted `ubuntu-24.04` runner (AMD EPYC, x86_64, kernel 7.0), from the manual `benchmarks` workflow: a shared VM, so noisy. Still the 0.1.0 measurement |
| [`results/mcp-latency-lima-ubuntu-24.04-ga-aarch64.md`](results/mcp-latency-lima-ubuntu-24.04-ga-aarch64.md) | Phase 6's measurement of `run_sandboxed` alone |

The JSON files are authoritative, and each Markdown file is generated from its JSON.

**Regenerate:**

```bash
# a full run; --readme also regenerates the README table from this result
PYTHONPATH=. uv run python benchmarks/bench.py run --env lima-ubuntu-24.04-ga-aarch64 \
  --label "development VM (Apple M2, Lima vz)" --readme
# only the README table, from the committed result
PYTHONPATH=. uv run python benchmarks/bench.py readme
```

**Requirements:**
- `strace`, for the `--trace` row;
- `bubblewrap`;
- `docker.io` installed in the VM (never Docker Desktop), used through `sudo -n`;
- passwordless `sudo`, for the Docker rows and the cold runs. Each cold run stops Docker,
  drops the page cache, and starts Docker again.

A configuration that cannot run is reported as `n/a`, with the reason, never left out.

bubblewrap cannot run unprivileged on either host measured: the stock Ubuntu 24.04 VM, or
GitHub's `ubuntu-24.04` runner. AppArmor restricts the unprivileged user namespaces it needs.
Measuring it would mean adding an AppArmor profile that grants it `userns`, a change to the
host's security configuration that was not made. Convergence needs no namespaces.
