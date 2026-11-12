# Escape matrix report

- launcher: `convergence`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `bd4d071adf173b61665f048ec92ed7e34baff21e`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T09:50:21+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| holdout | 26 | 1/22 (4.5%; Wilson 95% CI 0.8-21.8%) | n/a (nothing counted) | documented-limitation 1, escape 1, not-reached 3, pass 21 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `holdout-clone3-bypass-001` | holdout | attack | pass | every process of the run stayed in the runner's namespaces |
| `holdout-env-leak-001` | holdout | attack | pass | the supervisor's environment secret appeared in no output channel |
| `holdout-exec-disallowed-001` | holdout | attack | pass | the marker binary was never mapped executable |
| `holdout-exec-via-interpreter-001` | holdout | attack | pass | the marker script did not run |
| `holdout-exec-via-loader-001` | holdout | attack | escape | the marker binary was mapped executable in pid 63637 |
| `holdout-filesystem-delete-001` | holdout | attack | pass | the sentinel file is untouched |
| `holdout-filesystem-read-001` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-filesystem-read-002` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-filesystem-write-001` | holdout | attack | pass | nothing outside the write grants changed |
| `holdout-io-uring-bypass-001` | holdout | attack | pass | no process of the run held a io_uring descriptor |
| `holdout-mount-namespace-001` | holdout | attack | pass | every process of the run stayed in the runner's namespaces |
| `holdout-net-tcp-bind-001` | holdout | attack | pass | the harness never got the marker back from port 34287 |
| `holdout-net-tcp-connect-001` | holdout | attack | pass | the sink received nothing |
| `holdout-net-udp-001` | holdout | attack | not-reached | the sink received nothing; the payload never emitted ${REACHED}, so it may have been stopped before its attempt (emit it, flushed, just before attempting) |
| `holdout-persist-setsid-doublefork-001` | holdout | attack | pass | no process of the run outlived it |
| `holdout-proc-other-pid-002` | holdout | attack | pass | the sentinel's mapped pathname secret appeared in no output channel |
| `holdout-proc-self-001` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-ptrace-002` | holdout | attack | pass | the sentinel's in-memory secret appeared in no output channel |
| `holdout-resource-fork-bomb-001` | holdout | attack | pass | peak 3 processes added beyond the tool's own; policy allows 3 |
| `holdout-setuid-no-new-privs-001` | holdout | attack | not-reached | every process of the run kept the caller's uid and no capabilities; the payload never emitted ${REACHED}, so it may have been stopped before its attempt (emit it, flushed, just before attempting) |
| `holdout-signal-outside-001` | holdout | attack | documented-limitation | the sentinel received SIGUSR1 from the payload |
| `holdout-traversal-dotdot-001` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-traversal-hardlink-001` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-traversal-rename-refer-001` | holdout | attack | pass | nothing outside the write grants changed |
| `holdout-traversal-symlink-001` | holdout | attack | pass | the planted secret appeared in no output channel |
| `holdout-unix-socket-host-001` | holdout | attack | not-reached | the sink received nothing; the payload never emitted ${REACHED}, so it may have been stopped before its attempt (emit it, flushed, just before attempting) |
