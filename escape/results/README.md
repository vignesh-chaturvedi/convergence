# Escape-matrix results

Reports produced by `python -m escape.runner`. The JSON files are authoritative; each
Markdown file is generated from its JSON.

## Current

| File | Launcher | What it shows |
|---|---|---|
| `validity-lima-ubuntu-24.04-ga-aarch64.*` | unconfined | 45 of the 47 development attacks escape with nothing confining them, and all 10 controls do their job. The other 2 attacks are `not-testable`: this host refuses raw sockets and TIOCSTI before Convergence is involved. This is the validity gate: a case that fails it proves nothing. |
| `holdout-convergence-lima-ubuntu-24.04-ga-aarch64.*` | convergence | **The one holdout run under Convergence**, at commit `bd4d071`, reported as it came out. 21 attacks pass. 1 escapes: `holdout-exec-via-loader-001`, the dynamic-loader limitation; the known-limitations list never applies to the holdout. 1 is a documented limitation (signal scoping needs Landlock ABI 6). 3 are `not-reached`. Escape rate 1/22 (4.5%; Wilson 95% CI 0.8-21.8%). This file is never regenerated. |
| `validity-holdout-lima-ubuntu-24.04-ga-aarch64.*` | unconfined | All 26 independently authored holdout attacks escape with nothing confining them. Its cases are sealed by `escape/cases/holdout.sha256`. |
| `convergence-lima-ubuntu-24.04-ga-aarch64.*` | convergence | The development attacks and controls under `convergence run`: 53 attacks pass, 1 known limitation (`exec-via-loader-001`, the dynamic-loader case in THREAT_MODEL.md, counted as an escape), 1 documented limitation (`signal-outside-001`, needs Landlock ABI 6), 2 not testable. All 10 controls pass. Escape rate 1/44, false-denial rate 0/10. |

All three were generated on the Lima VM: Ubuntu 24.04.4, stock kernel 6.8.0-134-generic,
aarch64, Landlock ABI 4. Their `commit` field ends in `+uncommitted` because they were
produced from the working tree of the commit that adds them.

Every holdout run is appended to `escape/holdout-runs.jsonl` with its launcher. Apart from
the first line (the superseded corpus, below), all are unconfined validity runs of this
holdout: one found an invalid case, which was fixed; two cases were then replaced because
they read `/proc/<pid>/cmdline` with `/proc` granted, which the threat model leaves out of
scope; the final run is 26 of 26 valid. None of them ran Convergence.

## After the holdout run

Observations made after the holdout run, kept apart from its result. Nothing in the holdout
was changed.

- **The escape** is the same mechanism as the development case `exec-via-loader-001`: the
  dynamic loader maps a file the tool can only read. It is documented in THREAT_MODEL.md and
  is inherent to Landlock, so no fix follows from it.
- **The three `not-reached` cases** (`holdout-net-udp-001`, `holdout-setuid-no-new-privs-001`,
  `holdout-unix-socket-host-001`) prove nothing either way. In each, the run stopped before
  the case emitted `${REACHED}`. Their development counterparts had the same pattern and
  were corrected in Phase 4:
  - for UDP and unix sockets, creating the socket is the step Convergence's seccomp filter
    stops, and the marker came after it;
  - the setuid case needs a pseudo-terminal its policy may not grant.

  Whether that is what happened here would need the case files, which stay with the holdout
  author.
- If the holdout author corrects those cases, the corrected set is a new version. Its runs
  are no longer out-of-sample, because this result has been seen. They go in a separately
  named report and never replace this one.

## Superseded

`superseded/baseline-convergence-*` is the "initially red" baseline committed at the end of
Phase 3: `convergence run` did not exist yet, so every testable case was
`launcher-unavailable` and nothing was counted as a pass.

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
  --json escape/results/convergence-<env>.json \
  --markdown escape/results/convergence-<env>.md
```
