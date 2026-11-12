# Divergence reports used to test the importer

Real output of Divergence's dynamic tier, produced in the development VM by running
Divergence itself. They were not written by hand. The importer tests read them
(`tests/test_import_divergence.py`).

| | |
|---|---|
| Divergence | [vignesh-chaturvedi/divergence](https://github.com/vignesh-chaturvedi/divergence) at `8c15b5fe3cbcb084ce2a6615a47a06f5a8575edb` |
| Runner | `divergence-sandbox 1.1.0`, built with `cargo build --locked --release` (Rust 1.89.0) |
| Host | Ubuntu 24.04.4, kernel 6.8.0-134-generic, aarch64, Landlock ABI 4 |
| Artifact | [`probe-artifact/`](probe-artifact/), a benign MCP server written for this test |

The probe makes one call of each kind Divergence reports:
- it reads its own `data.csv`;
- it writes a summary to its temporary directory;
- it runs `/bin/true`;
- it tries a TCP connection, which Divergence's sandbox blocks;
- it reads the decoy credential Divergence plants in its private `HOME`.

It runs only inside Divergence's sandbox.

```bash
export DIVERGENCE_SANDBOX_BIN=$PWD/sandbox/target/release/divergence-sandbox
uv run divergence scan <probe-artifact> --dynamic --sandbox-timeout 30 --json > probe.scan.json
"$DIVERGENCE_SANDBOX_BIN" --timeout 30 <probe-artifact> > probe.sandbox.json
```

- `probe.sandbox.json`: the runner's own report, schema `divergence.sandbox/1`.
- `probe.scan.json`: `divergence scan --json`, which embeds the same data under
  `targets[].dynamic`. Its status is `partial`, because static analysis had nothing to
  analyse.

**One edit:** the VM user's home directory in paths was replaced with `/home/user`
(`sed s#/home/<vm-user>#/home/user#g`). Nothing else was changed.
