# Benchmarks

- **GitHub-hosted ubuntu-24.04 runner, x86_64 (a noisy shared VM)**: AMD EPYC 9V45 96-Core Processor, 4 CPUs, 15983 MiB; Ubuntu 24.04.5 LTS, kernel 7.0.0-1017-azure (x86_64); Python 3.12.3
- convergence 0.1.0.dev0 at `58c65eaa3f11f58fdcbb02246c0a7fc5e624c59b`; strace -- version 6.8; bubblewrap 0.9.0; Docker 28.0.4; image `python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`
- 200 measured runs per cell after 10 warm-up runs (docker-cold: 200, no warm-up); method in [ADR 0011](../../docs/adr/0011-benchmark-method.md)

| Configuration | `true` p50 (p95) ms | `python` p50 (p95) ms | `wordcount` p50 (p95) ms |
|---|---:|---:|---:|
| no sandbox (`subprocess`) | 0.41 (0.49) | 10.98 (13.09) | 22.14 (25.47) |
| `sudo -n true` (inside every Docker row) | 4.76 (5.13) | 4.81 (4.94) | 4.78 (5.7) |
| Convergence, library API, warm | 15.16 (18.22) | 27.53 (28.55) | 37.47 (71.39) |
| Convergence, library API, warm, `--trace` | 38.8 (39.9) | 67.69 (73.41) | 78.33 (87.62) |
| Convergence, one MCP `run_sandboxed` call | 16.7 (22.31) | 26.62 (30.68) | 38.41 (40.53) |
| Convergence CLI, cold process | 137.73 (148.7) | 149.26 (162.77) | 162.79 (179) |
| bubblewrap | n/a | n/a | n/a |
| `docker run --rm`, warm | 109.56 (129.85) | 120.94 (137.75) | 149.44 (168.79) |
| `docker run --rm`, cold daemon and cache | 263.29 (304.19) | 291.35 (338.95) | 325.45 (356.33) |

n/a: bwrap cannot run here: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted

| Configuration | Workload | Runs | p50 | p95 | p99 | mean | stdev |
|---|---|---:|---:|---:|---:|---:|---:|
| bare | true | 200 | 0.41 | 0.49 | 0.53 | 0.42 | 0.03 |
| bare | python | 200 | 10.98 | 13.09 | 19.86 | 11.39 | 1.83 |
| bare | wordcount | 200 | 22.14 | 25.47 | 30.18 | 22.51 | 2.32 |
| sudo | true | 200 | 4.76 | 5.13 | 5.76 | 4.8 | 0.24 |
| sudo | python | 200 | 4.81 | 4.94 | 5.11 | 4.81 | 0.09 |
| sudo | wordcount | 200 | 4.78 | 5.7 | 8.96 | 4.93 | 0.86 |
| convergence-api | true | 200 | 15.16 | 18.22 | 18.84 | 15.31 | 1.48 |
| convergence-api | python | 200 | 27.53 | 28.55 | 29.67 | 27.35 | 0.92 |
| convergence-api | wordcount | 200 | 37.47 | 71.39 | 121.36 | 42.31 | 19.04 |
| convergence-api-trace | true | 200 | 38.8 | 39.9 | 53.69 | 37.23 | 4.71 |
| convergence-api-trace | python | 200 | 67.69 | 73.41 | 100.94 | 67.0 | 7.77 |
| convergence-api-trace | wordcount | 200 | 78.33 | 87.62 | 115.69 | 81.04 | 17.15 |
| convergence-mcp | true | 200 | 16.7 | 22.31 | 38.99 | 16.84 | 4.37 |
| convergence-mcp | python | 200 | 26.62 | 30.68 | 45.92 | 27.76 | 4.11 |
| convergence-mcp | wordcount | 200 | 38.41 | 40.53 | 41.48 | 38.53 | 1.15 |
| convergence-cli | true | 200 | 137.73 | 148.7 | 171.53 | 139.02 | 9.15 |
| convergence-cli | python | 200 | 149.26 | 162.77 | 183.36 | 150.97 | 7.1 |
| convergence-cli | wordcount | 200 | 162.79 | 179.0 | 211.18 | 165.15 | 9.54 |
| docker-warm | true | 200 | 109.56 | 129.85 | 153.45 | 112.17 | 11.13 |
| docker-warm | python | 200 | 120.94 | 137.75 | 181.85 | 124.43 | 11.8 |
| docker-warm | wordcount | 200 | 149.44 | 168.79 | 191.39 | 150.07 | 10.39 |
| docker-cold | true | 200 | 263.29 | 304.19 | 312.43 | 266.23 | 14.55 |
| docker-cold | python | 200 | 291.35 | 338.95 | 372.33 | 297.02 | 20.35 |
| docker-cold | wordcount | 200 | 325.45 | 356.33 | 390.15 | 327.12 | 17.07 |
