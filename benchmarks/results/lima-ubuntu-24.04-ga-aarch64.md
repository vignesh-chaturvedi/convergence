# Benchmarks

- **development VM (Apple M2, Lima vz)**: -, 4 CPUs, 2898 MiB; Ubuntu 24.04.4 LTS, kernel 6.8.0-134-generic (aarch64); Python 3.12.3
- convergence 0.1.0.dev0 at `15352948b008b451255183d496754da2ab8db332+uncommitted`; strace -- version 6.8; bubblewrap 0.9.0; Docker 29.1.3; image `python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`
- 200 measured runs per cell after 10 warm-up runs (docker-cold: 200, no warm-up); method in [ADR 0011](../../docs/adr/0011-benchmark-method.md)

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

| Configuration | Workload | Runs | p50 | p95 | p99 | mean | stdev |
|---|---|---:|---:|---:|---:|---:|---:|
| bare | true | 200 | 0.21 | 0.27 | 0.78 | 0.23 | 0.1 |
| bare | python | 200 | 7.72 | 8.91 | 9.44 | 7.89 | 0.43 |
| bare | wordcount | 200 | 16.65 | 18.48 | 23.46 | 17.01 | 1.57 |
| sudo | true | 200 | 2.64 | 3.74 | 4.57 | 2.8 | 0.46 |
| sudo | python | 200 | 2.6 | 3.19 | 3.86 | 2.7 | 0.41 |
| sudo | wordcount | 200 | 2.66 | 3.84 | 8.51 | 2.91 | 0.92 |
| convergence-api | true | 200 | 7.89 | 10.62 | 13.1 | 8.32 | 1.19 |
| convergence-api | python | 200 | 16.41 | 21.06 | 23.54 | 17.18 | 2.05 |
| convergence-api | wordcount | 200 | 26.83 | 32.78 | 38.57 | 27.56 | 2.89 |
| convergence-api-trace | true | 200 | 23.09 | 26.58 | 29.93 | 23.44 | 1.94 |
| convergence-api-trace | python | 200 | 67.03 | 74.55 | 101.81 | 67.98 | 12.73 |
| convergence-api-trace | wordcount | 200 | 82.47 | 92.23 | 108.52 | 83.68 | 5.88 |
| convergence-mcp | true | 200 | 8.64 | 11.03 | 18.31 | 9.34 | 3.84 |
| convergence-mcp | python | 200 | 16.84 | 20.41 | 24.45 | 17.45 | 1.61 |
| convergence-mcp | wordcount | 200 | 26.6 | 34.02 | 79.02 | 29.15 | 13.4 |
| convergence-cli | true | 200 | 114.37 | 127.58 | 136.09 | 116.5 | 5.48 |
| convergence-cli | python | 200 | 122.65 | 135.06 | 149.31 | 125.59 | 10.54 |
| convergence-cli | wordcount | 200 | 132.79 | 147.29 | 157.8 | 135.09 | 6.52 |
| docker-warm | true | 200 | 106.64 | 139.13 | 191.95 | 110.4 | 17.14 |
| docker-warm | python | 200 | 116.17 | 139.36 | 161.9 | 119.44 | 13.06 |
| docker-warm | wordcount | 200 | 138.15 | 171.59 | 192.88 | 143.67 | 15.89 |
| docker-cold | true | 200 | 151.08 | 200.74 | 264.58 | 158.2 | 35.39 |
| docker-cold | python | 200 | 161.39 | 193.82 | 222.23 | 165.22 | 20.27 |
| docker-cold | wordcount | 200 | 195.47 | 348.86 | 773.57 | 231.29 | 170.33 |
