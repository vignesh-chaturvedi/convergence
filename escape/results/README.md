# Escape-matrix results

Reports produced by `python -m escape.runner`. The JSON files are authoritative; each
Markdown file is generated from its JSON.

## Current

| File | Launcher | What it shows |
|---|---|---|
| `validity-lima-ubuntu-24.04-ga-aarch64.*` | unconfined | 45 of the 47 development attacks escape with nothing confining them, and all 10 controls do their job. The other 2 attacks are `not-testable`: this host refuses raw sockets and TIOCSTI before Convergence is involved. This is the validity gate: a case that fails it proves nothing. |
| `validity-holdout-lima-ubuntu-24.04-ga-aarch64.*` | unconfined | All 26 independently authored holdout attacks escape with nothing confining them. Its cases are sealed by `escape/cases/holdout.sha256`. |
| `baseline-convergence-lima-ubuntu-24.04-ga-aarch64.*` | convergence | The "initially red" baseline: `convergence run` does not exist yet (Phase 4), so every testable case is `launcher-unavailable` and the run exits non-zero. Nothing is counted as a pass. |

All three were generated on the Lima VM: Ubuntu 24.04.4, stock kernel 6.8.0-134-generic,
aarch64, Landlock ABI 4. Their `commit` field ends in `+uncommitted` because they were
produced from the working tree of the commit that adds them.

Every holdout run is appended to `escape/holdout-runs.jsonl` with its launcher. Apart from
the first line (the superseded corpus, below), all are unconfined validity runs of this
holdout: one found an invalid case, which was fixed; two cases were then replaced because
they read `/proc/<pid>/cmdline` with `/proc` granted, which the threat model leaves out of
scope; the final run is 26 of 26 valid. None of them ran Convergence.

## Superseded

`superseded/validity-first-corpus-*` were produced on an Ubuntu 24.04.5 host (kernel 7.0,
x86_64, Landlock ABI 8) from the first version of the attack corpus. They are kept as a
record, not as evidence:

- the development report counts 48 cases, 7 of which repeated another case byte for byte;
  several of its cases also observed an effect another layer would stop (for example a
  canary read standing in for a seccomp rule), so a pass under Convergence would have
  credited the wrong mechanism;
- the holdout report covers 26 cases of which 25 are byte-identical to development cases,
  so it is a development result, not an out-of-sample one.

The one-line record of that holdout run is in `escape/holdout-runs.jsonl`.

## Regenerate

```bash
python -m escape.runner validity --set dev --set controls \
  --json escape/results/validity-<env>.json --markdown escape/results/validity-<env>.md
python -m escape.runner run --launcher convergence --set dev --set controls \
  --json escape/results/baseline-convergence-<env>.json \
  --markdown escape/results/baseline-convergence-<env>.md
```
