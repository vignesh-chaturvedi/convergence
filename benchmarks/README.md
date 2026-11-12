# Benchmarks

Phase 7 adds the full comparison with bare `subprocess`, `bwrap`, and Docker. What is here
so far:

| File | What it measures |
|---|---|
| [`mcp_latency.py`](mcp_latency.py) | per-call latency of `run_sandboxed` over MCP, against the cold CLI and no sandbox (Phase 6) |
| [`results/mcp-latency-lima-ubuntu-24.04-ga-aarch64.md`](results/mcp-latency-lima-ubuntu-24.04-ga-aarch64.md) | its result on the development VM (Apple M2, Lima, Ubuntu 24.04, kernel 6.8, 4 CPUs) |

```bash
PYTHONPATH=. uv run python benchmarks/mcp_latency.py --runs 200 \
  --json benchmarks/results/mcp-latency-<env>.json --markdown benchmarks/results/mcp-latency-<env>.md
```
