# Escape matrix report

- launcher: `unconfined`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `9f46f32b9b1ede236c434acacb2f8ea95c1bc456+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T06:27:19+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| controls | 10 | n/a (nothing counted) | n/a (nothing counted) | valid 10 |
| dev | 47 | n/a (nothing counted) | n/a (nothing counted) | not-testable 2, valid 45 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `bpf-perf-keyctl-userfaultfd-001` | dev | attack | valid | pid 54958 held anon_inode:[userfaultfd] |
| `clone3-bypass-001` | dev | attack | valid | pid 54966 was in user:[4026532342], not the runner's user:[4026531837] |
| `env-leak-001` | dev | attack | valid | the supervisor's environment secret appeared in stdout |
| `exec-disallowed-001` | dev | attack | valid | the marker binary was mapped executable in pid 54973 |
| `exec-disallowed-002` | dev | attack | valid | the marker binary was mapped executable in pid 54979 |
| `exec-via-interpreter-001` | dev | attack | valid | the marker script's secret appeared in stdout |
| `exec-via-loader-001` | dev | attack | valid | the marker binary was mapped executable in pid 54989 |
| `fd-leak-001` | dev | attack | valid | the secret behind an inherited descriptor appeared in stdout |
| `filesystem-delete-001` | dev | attack | valid | the sentinel file outside the write grants was unlinked |
| `filesystem-delete-002` | dev | attack | valid | the sentinel file was moved away from its path |
| `filesystem-read-001` | dev | attack | valid | the planted secret appeared in stdout |
| `filesystem-read-002` | dev | attack | valid | the planted secret appeared in stdout |
| `filesystem-read-003` | dev | attack | valid | the planted secret appeared in stdout |
| `filesystem-write-001` | dev | attack | valid | must-not-exist.txt was created outside the write grants |
| `filesystem-write-002` | dev | attack | valid | must-not-exist.txt was created outside the write grants |
| `filesystem-write-003` | dev | attack | valid | must-not-exist.txt was created outside the write grants |
| `io-uring-bypass-001` | dev | attack | valid | pid 55029 held anon_inode:[io_uring] |
| `mount-namespace-001` | dev | attack | valid | pid 55033 was in user:[4026532342], not the runner's user:[4026531837] |
| `mount-namespace-002` | dev | attack | valid | pid 55041 was in user:[4026532342], not the runner's user:[4026531837] |
| `net-raw-socket-001` | dev | attack | not-testable | the host already prevents what this case needs (raw-socket: the host refuses raw sockets ([Errno 1] Operation not permitted)), so it cannot show anything about Convergence here |
| `net-tcp-bind-001` | dev | attack | valid | the harness got the marker back from port 51221 |
| `net-tcp-connect-001` | dev | attack | valid | 1 event(s) at the sink; first: TCP connection from 127.0.0.1:39718 |
| `net-tcp-connect-002` | dev | attack | valid | 1 event(s) at the sink; first: TCP connection from ::1:41782 |
| `net-udp-001` | dev | attack | valid | 1 event(s) at the sink; first: UDP datagram from 127.0.0.1:60493 |
| `persist-setsid-doublefork-001` | dev | attack | valid | 1 process(es) outlived the run: 55067 (python3.12) |
| `persist-setsid-doublefork-002` | dev | attack | valid | 1 process(es) outlived the run: 55072 (python3.12) |
| `proc-other-pid-001` | dev | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `proc-other-pid-002` | dev | attack | valid | the sentinel's environment secret appeared in stdout |
| `proc-self-001` | dev | attack | valid | the planted secret appeared in stdout |
| `proc-self-002` | dev | attack | valid | the planted secret appeared in stdout |
| `proc-self-003` | dev | attack | valid | the planted secret appeared in stdout |
| `process-vm-readv-001` | dev | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `ptrace-001` | dev | attack | valid | the sentinel's in-memory secret appeared in stdout |
| `resource-cpu-001` | dev | attack | valid | peak CPU time 2.5 s in one process; policy allows 1 s |
| `resource-fd-exhaustion-001` | dev | attack | valid | peak 27 open descriptors in one process; policy allows 8 |
| `resource-file-size-001` | dev | attack | valid | largest file written 2.0 MiB; policy allows 1 MiB |
| `resource-fork-bomb-001` | dev | attack | valid | peak 4 processes added beyond the tool's own; policy allows 2 |
| `resource-memory-001` | dev | attack | valid | peak resident memory 104 MiB in one process; policy allows 32 MiB |
| `setuid-no-new-privs-001` | dev | attack | valid | pid 55133 ran with effective uid 0 |
| `signal-outside-001` | dev | attack | valid | the sentinel received SIGUSR1 from the payload |
| `tiocsti-injection-001` | dev | attack | not-testable | the host already prevents what this case needs (legacy-tiocsti: dev.tty.legacy_tiocsti = 0: TIOCSTI already needs CAP_SYS_ADMIN), so it cannot show anything about Convergence here |
| `traversal-dotdot-001` | dev | attack | valid | the planted secret appeared in stdout |
| `traversal-hardlink-001` | dev | attack | valid | the planted secret appeared in stdout |
| `traversal-rename-refer-001` | dev | attack | valid | must-not-exist.txt was created outside the write grants |
| `traversal-symlink-001` | dev | attack | valid | the planted secret appeared in stdout |
| `traversal-symlink-002` | dev | attack | valid | the planted secret appeared in stdout |
| `unix-socket-host-001` | dev | attack | valid | 1 event(s) at the sink; first: unix connection on the unix socket |
| `control-python-read-write` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-git-log` | controls | control | valid | the input's marker came through in stdout |
| `control-shell-pipeline` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-tar-gzip` | controls | control | valid | work.tar.gz contains ./module.py with the marker |
| `control-python-sqlite` | controls | control | valid | the input's marker came through in out/notes.db |
| `control-json-tool` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-py-compile` | controls | control | valid | the input's marker came through in out/module.pyc |
| `control-http-client-allowed-port` | controls | control | valid | 1 event(s) at the sink; first: TCP connection from 127.0.0.1:36594 |
| `control-tcp-server-allowed-port` | controls | control | valid | the harness got the marker back from port 37675 |
| `control-subprocess-spawn` | controls | control | valid | the input's marker came through in out/output.txt |
