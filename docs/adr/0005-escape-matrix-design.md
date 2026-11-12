# ADR 0005 — Escape-matrix design: external oracles, validity, and a sealed holdout

**Status:** accepted · **Phase:** 3 · **Date:** 2026-11-11 (implementation notes 2026-11-12)

## Context

The escape matrix is the evidence that Convergence does what it claims. It is a corpus of
attack cases, each with an expected verdict, run against a real kernel. Its credibility
rests on three things being right, and all three are design decisions made *before* the
runtime exists so that the runtime cannot be built to flatter them:

1. a case must prove the dangerous thing really happens, not merely that the tool said so;
2. a case must prove the attack is real, by succeeding when nothing confines it;
3. the author of the corpus must not be able to tune the runtime against the whole corpus.

The full specification the implementer follows is [escape/README.md](../../escape/README.md).
This ADR records the decisions and why.

## Decision

### Every case uses an external oracle

The verdict of a case is decided by **ground truth the harness controls**, never by output
the payload produces about itself. A payload that prints "I read the secret" is not
evidence; a payload that copies a secret the harness planted, to a channel the harness can
read, is. Concretely:

- secrets are random nonces the harness plants and then searches for in the payload's
  allowed output channels;
- forbidden writes are checked on the host filesystem after the run;
- network reach is checked at a harness-owned sink socket;
- process tampering is checked at a harness-owned sentinel;
- denial of service and persistence are checked by host-side measurement (elapsed time,
  surviving processes, file sizes, descriptor counts).

A payload's self-report is advisory at most. This is the same discipline the project exists
to enforce on others: a finding is the observed effect, not the claim.

### Validity: every attack must escape when unconfined

The runner has a launcher abstraction with two backends:

- `unconfined` — no sandbox: the payload inherits the launching process's whole
  environment and any descriptors the oracle leaks, as a run with nothing protecting it
  would. Only harness safety rlimits apply, set at four times the policy's limits so a
  validity run can exceed the policy without taking the host down. Available now;
- `convergence` — `convergence run` with the case's policy, available from Phase 4.

Before an attack counts, it must produce **escaped** under the `unconfined` launcher: the
oracle must observe the bad effect with nothing stopping it. An attack that cannot escape
unconfined proves nothing and is rejected in review. Controls must likewise **succeed**
unconfined. This gate runs in Phase 3, before any enforcement exists, and its results are
committed.

### The matrix is "initially failing"

Until Phase 4 builds `convergence run`, the `convergence` launcher reports every case as
`launcher-unavailable`: nothing is executed, and the run fails. A case that did not run is
never counted as a pass. That red baseline is committed. Phase 4's job is to make the
launcher real and drive the escape rate to zero (or document each remaining escape as a
known limitation). Writing the matrix first, red, is deliberate: the tests are not shaped to
fit an implementation that does not yet exist.

### ABI-aware expectations, so limitations are not counted as surprises

An attack declares the mechanism expected to stop it and the minimum Landlock ABI that
mechanism needs. On a kernel below that ABI with no fallback, the case is a **documented
limitation** (expected to escape, recorded as such), not a test failure. This keeps the
headline escape rate honest on stock Ubuntu 24.04 (ABI 4), where signal scoping and UDP port
limiting are genuinely unavailable (THREAT_MODEL.md). A case that should be blocked on *all*
supported kernels declares no ABI floor, and any escape there is a real failure.

### A sealed holdout, now made more independent

The corpus is split, stratified by category, into a development set the implementer may run
freely and a **holdout** the implementer does not look at while tuning. Targets: at least
45 development attacks, 20 holdout attacks, and 10 benign controls.

- The holdout files are fixed by `escape/cases/holdout.sha256`, a manifest of per-file
  SHA-256 digests plus a digest over the sorted manifest, committed in this phase.
- A test verifies the holdout files still match the manifest, so an edit cannot pass
  unnoticed; any change is visible in git history and changes the sealed digest.
- The runner refuses to execute holdout cases without an explicit one-time `--holdout-run`
  flag, and appends every holdout run to `escape/holdout-runs.log` with the commit SHA,
  kernel, ABI, and architecture.

The holdout reduces but does not remove author bias, and the project says so. In this build
the bias is further reduced by circumstance: the holdout is authored in Phase 3, and the
runtime it tests is written afterwards by a different author. The two are therefore more
independent than a single author writing both, though the corpus and the project still share
an origin.

### No mocks for security behaviour

Every case runs against a real kernel — the Lima VM locally and GitHub Actions in CI,
including the nested VM on the stock 24.04 kernel. Nothing about enforcement is mocked. The
CI escape job is added in this phase and allowed to fail until Phase 4.

## Consequences

- The oracle requirement makes cases more work to write — each needs a planted nonce or a
  harness-side sink or sentinel — but it removes the single most common way a security
  benchmark lies to its author.
- The unconfined-validity gate can run and be committed now, so Phase 3 produces real
  evidence (every attack escapes unconfined; the confined matrix is red) before enforcement
  exists.
- Because expectations are ABI-aware, the same corpus runs on ABI 4 and ABI 8 and reports
  different, honest results on each, rather than a single number that hides the stock-kernel
  limitations.
- The holdout discipline costs a one-time flag and a log, and forbids consulting the holdout
  during Phase 4. The payoff is an out-of-sample number that a reader can trust more than the
  development set.
- Two numbers are reported, escape rate and false-denial rate, because a sandbox can cheat
  either by being too loose (escapes) or too tight (false denials). Reporting only one would
  hide the other failure mode.
