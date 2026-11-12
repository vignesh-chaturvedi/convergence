# Escape-matrix results

Reports produced by `python -m escape.runner`. The JSON files are authoritative; each
Markdown file is generated from its JSON.

| File | Launcher | What it shows |
|---|---|---|
| `validity-lima-ubuntu-24.04-ga-aarch64.*` | unconfined | Every benign control does its job with nothing confining it (10/10 valid). This is the validity gate: a control that fails unconfined proves nothing. |
| `baseline-convergence-lima-ubuntu-24.04-ga-aarch64.*` | convergence | The "initially red" baseline: `convergence run` does not exist yet (Phase 4), so every case is `launcher-unavailable` and the run exits non-zero. Nothing is counted as a pass. |

Both were generated on the Lima VM (Ubuntu 24.04.4, stock kernel 6.8.0-134-generic,
aarch64, Landlock ABI 4). Their `commit` field reads `5038589…+uncommitted` because they
were produced from the working tree of the commit that adds the harness, before it was
committed.

**What is not here yet:** the attack cases. `escape/cases/dev/` and `escape/cases/holdout/`
are empty in this commit, so these reports contain no attack results and no escape rate.
The attack corpus (at least 45 development and 20 holdout cases) is written separately; its
validity run (every attack must escape unconfined) is committed when it lands, and the
holdout is sealed with `python -m escape.runner seal-holdout`.

Regenerate:

```bash
python -m escape.runner validity --set dev --set controls \
  --json escape/results/validity-<env>.json --markdown escape/results/validity-<env>.md
python -m escape.runner run --launcher convergence --set dev --set controls \
  --json escape/results/baseline-convergence-<env>.json \
  --markdown escape/results/baseline-convergence-<env>.md
```
