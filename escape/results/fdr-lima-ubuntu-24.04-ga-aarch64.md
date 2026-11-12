# False-denial rates of generated policies

- kernel: 6.8.0-134-generic (aarch64), Ubuntu 24.04.4 LTS, Landlock ABI 4
- commit: `764c6c95e53a3269e65ca92b997339f2cff3db18+uncommitted`, convergence 0.1.0.dev0

Each control was observed once with input A, a policy was generated from that observation, and the control was then run under it with input A and with input B.

| Rate | Value |
|---|---|
| same-input false-denial rate | 0/10 (0.0%; Wilson 95% CI 0.0-27.8%) |
| varied-input false-denial rate | 3/10 (30.0%; Wilson 95% CI 10.8-60.3%) |

| Control | Observed | Rules | Same input | Varied input | Evidence (varied) |
|---|---|---:|---|---|---|
| `control-python-read-write` | pass | 15 | pass | pass | the input's marker came through in out/output.txt |
| `control-git-log` | pass | 17 | pass | false-denial | the input's marker did not reach the expected output |
| `control-shell-pipeline` | pass | 19 | pass | pass | the input's marker came through in out/output.txt |
| `control-tar-gzip` | pass | 16 | pass | pass | work.tar.gz contains ./module.py with the marker |
| `control-python-sqlite` | pass | 16 | pass | pass | the input's marker came through in out/notes.db |
| `control-json-tool` | pass | 15 | pass | pass | the input's marker came through in out/output.txt |
| `control-py-compile` | pass | 15 | pass | pass | the input's marker came through in out/module.pyc |
| `control-http-client-allowed-port` | pass | 17 | pass | false-denial | the sink received nothing |
| `control-tcp-server-allowed-port` | pass | 15 | pass | false-denial | the harness never got the marker back from port 55543 |
| `control-subprocess-spawn` | pass | 17 | pass | pass | the input's marker came through in out/output.txt |
