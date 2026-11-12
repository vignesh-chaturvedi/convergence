# Escape matrix report

- launcher: `convergence`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `5038589685e97a01763ac68046f733069120595b+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T01:21:30+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| controls | 10 | n/a (nothing counted) | n/a (nothing counted) | launcher-unavailable 10 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `control-python-read-write` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-git-log` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-shell-pipeline` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-tar-gzip` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-python-sqlite` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-json-tool` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-py-compile` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-http-client-allowed-port` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-tcp-server-allowed-port` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `control-subprocess-spawn` | controls | control | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
