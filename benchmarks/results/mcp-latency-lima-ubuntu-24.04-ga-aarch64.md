# Per-call latency of `run_sandboxed` over MCP

Workload `/usr/bin/true`; kernel 6.8.0-134-generic (aarch64), 4 CPUs, Python 3.12.3.

| Path | Runs | p50 ms | p95 ms | p99 ms | mean ms | stdev ms |
|---|---:|---:|---:|---:|---:|---:|
| no sandbox (`subprocess`) | 200 | 0.19 | 0.49 | 1.1 | 0.25 | 0.33 |
| `run_sandboxed`, warm MCP session | 200 | 9.49 | 13.14 | 16.54 | 10.06 | 1.71 |
| `convergence run`, cold CLI | 100 | 127.45 | 144.46 | 155.3 | 129.74 | 14.25 |
