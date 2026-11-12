# Benchmarks

What it costs to start a tool under Convergence, compared with no sandbox, bubblewrap, and
Docker. The method is fixed in [ADR 0011](../docs/adr/0011-benchmark-method.md):
- which configurations are run, and what "cold" means;
- three workloads: `/usr/bin/true`, `python3 -c pass`, and a 1 MiB word count;
- at least 200 measured runs per cell.

| Result | Where |
|---|---|
| [`results/lima-ubuntu-24.04-ga-aarch64.md`](results/lima-ubuntu-24.04-ga-aarch64.md) | the development VM: Apple M2 under Lima (`vz`), Ubuntu 24.04, stock kernel 6.8. The README table is generated from its JSON |
| `results/gha-ubuntu-24.04-x86_64.md` | a GitHub-hosted `ubuntu-24.04` runner (x86_64), from the manual `benchmarks` workflow: a shared VM, so noisy |
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

A configuration that cannot run is reported as `n/a`, with the reason, never left out. On
stock Ubuntu 24.04, bubblewrap cannot run unprivileged: AppArmor restricts unprivileged user
namespaces, which it needs. Convergence needs none.
