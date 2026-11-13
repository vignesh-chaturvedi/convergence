# Benchmarks

- **development VM (Apple M2, Lima vz)**: -, 4 CPUs, 2898 MiB; Ubuntu 24.04.4 LTS, kernel 6.8.0-134-generic (aarch64); Python 3.12.3
- convergence 0.1.1 at `f4fcc8eb937b2e5e79437cdf81238eb8f09c02b8`; strace -- version 6.8; bubblewrap 0.9.0; Docker 29.1.3; image `python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`
- 200 measured runs per cell after 10 warm-up runs (docker-cold: 200, no warm-up); method in [ADR 0011](../../docs/adr/0011-benchmark-method.md)

| Configuration | `true` p50 (p95) ms | `python` p50 (p95) ms | `wordcount` p50 (p95) ms |
|---|---:|---:|---:|
| no sandbox (`subprocess`) | 0.2 (0.3) | 7.86 (8.63) | 16.84 (21.81) |
| `sudo -n true` (inside every Docker row) | 2.59 (3.26) | 2.6 (3.43) | 2.6 (3.99) |
| Convergence, library API, warm | 8.66 (11.26) | 20.4 (61.47) | 26.95 (78.61) |
| Convergence, library API, warm, `--trace` | 23.28 (25.59) | 68.44 (104.56) | 84.95 (94.07) |
| Convergence, one MCP `run_sandboxed` call | 10.07 (13.96) | 18.38 (23.48) | 28.53 (41.1) |
| Convergence CLI, cold process | 119.65 (136.88) | 128.58 (147.85) | 139.1 (177.02) |
| bubblewrap | n/a | n/a | n/a |
| `docker run --rm`, warm | 115.55 (200.73) | 124.23 (159.5) | 170.89 (275.27) |
| `docker run --rm`, cold daemon and cache | 217.97 (466.63) | 284.86 (829.34) | 208.95 (381.71) |

n/a: bwrap cannot run here: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted

| Configuration | Workload | Runs | p50 | p95 | p99 | mean | stdev |
|---|---|---:|---:|---:|---:|---:|---:|
| bare | true | 200 | 0.2 | 0.3 | 0.64 | 0.22 | 0.1 |
| bare | python | 200 | 7.86 | 8.63 | 9.92 | 7.99 | 0.4 |
| bare | wordcount | 200 | 16.84 | 21.81 | 27.78 | 17.66 | 2.43 |
| sudo | true | 200 | 2.59 | 3.26 | 3.42 | 2.68 | 0.25 |
| sudo | python | 200 | 2.6 | 3.43 | 5.24 | 2.76 | 0.47 |
| sudo | wordcount | 200 | 2.6 | 3.99 | 5.27 | 2.81 | 0.79 |
| convergence-api | true | 200 | 8.66 | 11.26 | 18.32 | 9.26 | 2.92 |
| convergence-api | python | 200 | 20.4 | 61.47 | 72.16 | 32.5 | 26.87 |
| convergence-api | wordcount | 200 | 26.95 | 78.61 | 108.31 | 32.44 | 17.39 |
| convergence-api-trace | true | 200 | 23.28 | 25.59 | 28.54 | 23.5 | 1.77 |
| convergence-api-trace | python | 200 | 68.44 | 104.56 | 153.68 | 74.18 | 25.97 |
| convergence-api-trace | wordcount | 200 | 84.95 | 94.07 | 111.47 | 85.55 | 6.6 |
| convergence-mcp | true | 200 | 10.07 | 13.96 | 17.41 | 10.58 | 1.66 |
| convergence-mcp | python | 200 | 18.38 | 23.48 | 28.48 | 19.23 | 2.09 |
| convergence-mcp | wordcount | 200 | 28.53 | 41.1 | 58.63 | 30.99 | 10.16 |
| convergence-cli | true | 200 | 119.65 | 136.88 | 190.08 | 123.17 | 12.3 |
| convergence-cli | python | 200 | 128.58 | 147.85 | 159.44 | 131.47 | 7.95 |
| convergence-cli | wordcount | 200 | 139.1 | 177.02 | 223.07 | 146.37 | 20.08 |
| docker-warm | true | 200 | 115.55 | 200.73 | 235.1 | 128.51 | 36.05 |
| docker-warm | python | 200 | 124.23 | 159.5 | 237.56 | 129.99 | 23.98 |
| docker-warm | wordcount | 200 | 170.89 | 275.27 | 576.98 | 188.14 | 77.64 |
| docker-cold | true | 200 | 217.97 | 466.63 | 660.31 | 257.12 | 116.12 |
| docker-cold | python | 200 | 284.86 | 829.34 | 1321.99 | 369.34 | 232.96 |
| docker-cold | wordcount | 200 | 208.95 | 381.71 | 582.46 | 239.26 | 80.74 |
