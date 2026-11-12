# Escape matrix report

- launcher: `unconfined`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `12415a134eb52817d080aea400e966ae49fa7b93+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T08:11:07+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| holdout | 26 | n/a (nothing counted) | n/a (nothing counted) | valid 26 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `holdout-clone3-bypass-001` | holdout | attack | valid | pid 56434 was in user:[4026532342], not the runner's user:[4026531837] |
| `holdout-env-leak-001` | holdout | attack | valid | the supervisor's environment secret appeared in stdout |
| `holdout-exec-disallowed-001` | holdout | attack | valid | the marker binary was mapped executable in pid 56441 |
| `holdout-exec-via-interpreter-001` | holdout | attack | valid | the marker script's secret appeared in stdout |
| `holdout-exec-via-loader-001` | holdout | attack | valid | the marker binary was mapped executable in pid 56451 |
| `holdout-filesystem-delete-001` | holdout | attack | valid | the sentinel file's contents changed |
| `holdout-filesystem-read-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-filesystem-read-002` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-filesystem-write-001` | holdout | attack | valid | must-not-exist.txt was created outside the write grants |
| `holdout-io-uring-bypass-001` | holdout | attack | valid | pid 56471 held anon_inode:[io_uring] |
| `holdout-mount-namespace-001` | holdout | attack | valid | pid 56479 was in user:[4026532342], not the runner's user:[4026531837] |
| `holdout-net-tcp-bind-001` | holdout | attack | valid | the harness got the marker back from port 60721 |
| `holdout-net-tcp-connect-001` | holdout | attack | valid | 1 event(s) at the sink; first: TCP connection from 127.0.0.1:58474 |
| `holdout-net-udp-001` | holdout | attack | valid | 1 event(s) at the sink; first: UDP datagram from ::1:46301 |
| `holdout-persist-setsid-doublefork-001` | holdout | attack | valid | 1 process(es) outlived the run: 56499 (sleep) |
| `holdout-proc-other-pid-002` | holdout | attack | valid | the sentinel's mapped pathname secret appeared in stdout |
| `holdout-proc-self-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-ptrace-002` | holdout | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `holdout-resource-fork-bomb-001` | holdout | attack | valid | peak 6 processes added beyond the tool's own; policy allows 3 |
| `holdout-setuid-no-new-privs-001` | holdout | attack | valid | pid 56528 ran with effective uid 0 |
| `holdout-signal-outside-001` | holdout | attack | valid | the sentinel received SIGUSR1 from the payload |
| `holdout-traversal-dotdot-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-traversal-hardlink-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-traversal-rename-refer-001` | holdout | attack | valid | must-not-exist.txt was created outside the write grants |
| `holdout-traversal-symlink-001` | holdout | attack | valid | the planted secret appeared in stdout |
| `holdout-unix-socket-host-001` | holdout | attack | valid | 1 event(s) at the sink; first: unix connection on the unix socket |
