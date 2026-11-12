# Escape matrix report

- launcher: `convergence`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `f00d0027d287381f63b2facadd7e7d072a36592e+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T08:55:14+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| controls | 10 | n/a (nothing counted) | 0/10 (0.0%; Wilson 95% CI 0.0-27.8%) | pass 10 |
| dev | 47 | 1/44 (2.3%; Wilson 95% CI 0.4-11.8%) | n/a (nothing counted) | documented-limitation 1, escape 1, not-testable 2, pass 43 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `bpf-perf-keyctl-userfaultfd-001` | dev | attack | pass | no process of the run held a userfaultfd descriptor |
| `clone3-bypass-001` | dev | attack | pass | every process of the run stayed in the runner's namespaces |
| `env-leak-001` | dev | attack | pass | the supervisor's environment secret appeared in no output channel |
| `exec-disallowed-001` | dev | attack | pass | the marker binary was never mapped executable |
| `exec-disallowed-002` | dev | attack | pass | the marker binary was never mapped executable |
| `exec-via-interpreter-001` | dev | attack | pass | the marker script did not run |
| `exec-via-loader-001` | dev | attack | escape | the marker binary was mapped executable in pid 60003 |
| `fd-leak-001` | dev | attack | pass | the secret behind the supervisor's descriptor appeared nowhere |
| `filesystem-delete-001` | dev | attack | pass | the sentinel file is untouched |
| `filesystem-delete-002` | dev | attack | pass | the sentinel file is untouched |
| `filesystem-read-001` | dev | attack | pass | the planted secret appeared in no output channel |
| `filesystem-read-002` | dev | attack | pass | the planted secret appeared in no output channel |
| `filesystem-read-003` | dev | attack | pass | the planted secret appeared in no output channel |
| `filesystem-write-001` | dev | attack | pass | nothing outside the write grants changed |
| `filesystem-write-002` | dev | attack | pass | nothing outside the write grants changed |
| `filesystem-write-003` | dev | attack | pass | nothing outside the write grants changed |
| `io-uring-bypass-001` | dev | attack | pass | no process of the run held a io_uring descriptor |
| `mount-namespace-001` | dev | attack | pass | every process of the run stayed in the runner's namespaces |
| `mount-namespace-002` | dev | attack | pass | every process of the run stayed in the runner's namespaces |
| `net-raw-socket-001` | dev | attack | not-testable | the host already prevents what this case needs (raw-socket: the host refuses raw sockets ([Errno 1] Operation not permitted)), so it cannot show anything about Convergence here |
| `net-tcp-bind-001` | dev | attack | pass | the harness never got the marker back from port 42253 |
| `net-tcp-connect-001` | dev | attack | pass | the sink received nothing |
| `net-tcp-connect-002` | dev | attack | pass | the sink received nothing |
| `net-udp-001` | dev | attack | pass | the sink received nothing |
| `persist-setsid-doublefork-001` | dev | attack | pass | no process of the run outlived it |
| `persist-setsid-doublefork-002` | dev | attack | pass | no process of the run outlived it |
| `proc-other-pid-001` | dev | attack | pass | the sentinel's in-memory secret appeared in no output channel |
| `proc-other-pid-002` | dev | attack | pass | the sentinel's environment secret appeared in no output channel |
| `proc-self-001` | dev | attack | pass | the planted secret appeared in no output channel |
| `proc-self-002` | dev | attack | pass | the planted secret appeared in no output channel |
| `proc-self-003` | dev | attack | pass | the planted secret appeared in no output channel |
| `process-vm-readv-001` | dev | attack | pass | the sentinel's in-memory secret appeared in no output channel |
| `ptrace-001` | dev | attack | pass | the sentinel's in-memory secret appeared in no output channel |
| `resource-cpu-001` | dev | attack | pass | peak CPU time 1.0 s in one process; policy allows 1 s |
| `resource-fd-exhaustion-001` | dev | attack | pass | peak 8 open descriptors in one process; policy allows 8 |
| `resource-file-size-001` | dev | attack | pass | largest file written 1.0 MiB; policy allows 1 MiB |
| `resource-fork-bomb-001` | dev | attack | pass | peak 2 processes added beyond the tool's own; policy allows 2 |
| `resource-memory-001` | dev | attack | pass | peak resident memory 24 MiB in one process; policy allows 32 MiB |
| `setuid-no-new-privs-001` | dev | attack | pass | every process of the run kept the caller's uid and no capabilities |
| `signal-outside-001` | dev | attack | documented-limitation | the sentinel received SIGUSR1 from the payload |
| `tiocsti-injection-001` | dev | attack | not-testable | the host already prevents what this case needs (legacy-tiocsti: dev.tty.legacy_tiocsti = 0: TIOCSTI already needs CAP_SYS_ADMIN), so it cannot show anything about Convergence here |
| `traversal-dotdot-001` | dev | attack | pass | the planted secret appeared in no output channel |
| `traversal-hardlink-001` | dev | attack | pass | the planted secret appeared in no output channel |
| `traversal-rename-refer-001` | dev | attack | pass | nothing outside the write grants changed |
| `traversal-symlink-001` | dev | attack | pass | the planted secret appeared in no output channel |
| `traversal-symlink-002` | dev | attack | pass | the planted secret appeared in no output channel |
| `unix-socket-host-001` | dev | attack | pass | the sink received nothing |
| `control-python-read-write` | controls | control | pass | the input's marker came through in out/output.txt |
| `control-git-log` | controls | control | pass | the input's marker came through in stdout |
| `control-shell-pipeline` | controls | control | pass | the input's marker came through in out/output.txt |
| `control-tar-gzip` | controls | control | pass | work.tar.gz contains ./module.py with the marker |
| `control-python-sqlite` | controls | control | pass | the input's marker came through in out/notes.db |
| `control-json-tool` | controls | control | pass | the input's marker came through in out/output.txt |
| `control-py-compile` | controls | control | pass | the input's marker came through in out/module.pyc |
| `control-http-client-allowed-port` | controls | control | pass | 1 event(s) at the sink; first: TCP connection from 127.0.0.1:40330 |
| `control-tcp-server-allowed-port` | controls | control | pass | the harness got the marker back from port 51335 |
| `control-subprocess-spawn` | controls | control | pass | the input's marker came through in out/output.txt |
