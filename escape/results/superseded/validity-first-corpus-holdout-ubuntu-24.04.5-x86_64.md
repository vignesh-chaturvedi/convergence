# Escape matrix report

- launcher: `unconfined`
- kernel: 7.0.0-1013-oracle (x86_64), Ubuntu 24.04.5 LTS, Landlock ABI 8
- commit: `d9633333a402d1c734522679a5c00ba1436954b1+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T03:01:59+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| holdout | 26 | n/a (nothing counted) | n/a (nothing counted) | not-testable 1, valid 25 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `holdout-clone3-bypass-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-env-leak-001` | holdout | attack | valid | the supervisor's environment secret appeared in stdout |
| `holdout-exec-disallowed-001` | holdout | attack | valid | the marker binary was mapped executable in pid 1662231 |
| `holdout-exec-via-interpreter-001` | holdout | attack | valid | the marker script's secret appeared in stdout |
| `holdout-exec-via-loader-001` | holdout | attack | valid | the marker binary was mapped executable in pid 1662239 |
| `holdout-filesystem-delete-001` | holdout | attack | valid | the sentinel file was moved away from its path |
| `holdout-filesystem-read-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-filesystem-read-002` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-filesystem-write-001` | holdout | attack | valid | must-not-exist.txt was created outside the write grants |
| `holdout-io-uring-bypass-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-mount-namespace-001` | holdout | attack | not-testable | the host already prevents what this case needs (unprivileged-userns: unprivileged user namespaces are refused here (map_ids: EACCES)), so it cannot show anything about Convergence here |
| `holdout-net-tcp-bind-001` | holdout | attack | valid | the harness got the marker back from port 53989 |
| `holdout-net-tcp-connect-001` | holdout | attack | valid | 1 event(s) at the sink; first: TCP connection from ::1:48764 |
| `holdout-net-udp-001` | holdout | attack | valid | 1 event(s) at the sink; first: UDP datagram from 127.0.0.1:52313 |
| `holdout-persist-setsid-doublefork-001` | holdout | attack | valid | 1 process(es) outlived the run: 1662288 (python3.12) |
| `holdout-proc-other-pid-001` | holdout | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `holdout-proc-self-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-ptrace-001` | holdout | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `holdout-resource-fork-bomb-001` | holdout | attack | valid | peak 5 concurrent processes; policy allows 2 |
| `holdout-setuid-no-new-privs-001` | holdout | attack | valid | pid 1662315 ran with effective uid 0 |
| `holdout-signal-outside-001` | holdout | attack | valid | the sentinel received SIGUSR1 from the payload |
| `holdout-traversal-dotdot-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-traversal-hardlink-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-traversal-rename-refer-001` | holdout | attack | valid | must-not-exist.txt was created outside the write grants |
| `holdout-traversal-symlink-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-unix-socket-host-001` | holdout | attack | valid | 1 event(s) at the sink; first: unix connection on the unix socket |
