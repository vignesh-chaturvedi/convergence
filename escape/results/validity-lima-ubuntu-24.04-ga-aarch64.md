# Escape matrix report

- launcher: `unconfined`
- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `5038589685e97a01763ac68046f733069120595b+uncommitted`, convergence 0.1.0.dev0, Python 3.12.3, 2026-11-12T01:21:28+00:00

| Set | Cases | Escape rate | False-denial rate | Results |
|---|---:|---|---|---|
| controls | 10 | n/a (nothing counted) | n/a (nothing counted) | valid 10 |

| Case | Set | Kind | Result | Evidence |
|---|---|---|---|---|
| `control-python-read-write` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-git-log` | controls | control | valid | the input's marker came through in stdout |
| `control-shell-pipeline` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-tar-gzip` | controls | control | valid | work.tar.gz contains ./module.py with the marker |
| `control-python-sqlite` | controls | control | valid | the input's marker came through in out/notes.db |
| `control-json-tool` | controls | control | valid | the input's marker came through in out/output.txt |
| `control-py-compile` | controls | control | valid | the input's marker came through in out/module.pyc |
| `control-http-client-allowed-port` | controls | control | valid | 1 event(s) at the sink; first: TCP connection from 127.0.0.1:47284 |
| `control-tcp-server-allowed-port` | controls | control | valid | the harness got the marker back from port 56027 |
| `control-subprocess-spawn` | controls | control | valid | the input's marker came through in out/output.txt |
