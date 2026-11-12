# Escape matrix report

- launcher: `convergence`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `12415a134eb52817d080aea400e966ae49fa7b93+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T07:10:59+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| controls | 10 | n/a (nothing counted) | n/a (nothing counted) | launcher-unavailable 10 |
| dev | 47 | n/a (nothing counted) | n/a (nothing counted) | launcher-unavailable 45, not-testable 2 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `bpf-perf-keyctl-userfaultfd-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `clone3-bypass-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `env-leak-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `exec-disallowed-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `exec-disallowed-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `exec-via-interpreter-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `exec-via-loader-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `fd-leak-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-delete-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-delete-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-read-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-read-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-read-003` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-write-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-write-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `filesystem-write-003` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `io-uring-bypass-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `mount-namespace-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `mount-namespace-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `net-raw-socket-001` | dev | attack | not-testable | the host already prevents what this case needs (raw-socket: the host refuses raw sockets ([Errno 1] Operation not permitted)), so it cannot show anything about Convergence here |
| `net-tcp-bind-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `net-tcp-connect-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `net-tcp-connect-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `net-udp-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `persist-setsid-doublefork-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `persist-setsid-doublefork-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `proc-other-pid-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `proc-other-pid-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `proc-self-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `proc-self-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `proc-self-003` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `process-vm-readv-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `ptrace-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `resource-cpu-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `resource-fd-exhaustion-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `resource-file-size-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `resource-fork-bomb-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `resource-memory-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `setuid-no-new-privs-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `signal-outside-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `tiocsti-injection-001` | dev | attack | not-testable | the host already prevents what this case needs (legacy-tiocsti: dev.tty.legacy_tiocsti = 0: TIOCSTI already needs CAP_SYS_ADMIN), so it cannot show anything about Convergence here |
| `traversal-dotdot-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `traversal-hardlink-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `traversal-rename-refer-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `traversal-symlink-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `traversal-symlink-002` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
| `unix-socket-host-001` | dev | attack | launcher-unavailable | `convergence run` is not implemented yet (Phase 4 in PLAN.md); nothing was executed |
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
