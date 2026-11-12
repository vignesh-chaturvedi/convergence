"""False-denial rates of generated policies (Phase 5).

For each benign control:
1. observe it with input A (``convergence observe``); this must succeed;
2. generate a policy from that one observation (``convergence generate``);
3. run it under the generated policy with input A again, for the *same-input* rate;
4. and with input B, for the *varied-input* rate.

Input B has more content and files that input A does not have, and network controls use a
different port. So the varied-input rate measures how incomplete a single observation is.

Each control runs in a fixed directory, so paths recorded while observing still exist
when the policy runs. A false denial means the generated policy stopped a benign workload.

    python -m escape.fdr [--case ID] --json R.json --markdown R.md [--policies DIR]
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from convergence.generate.policy import generate, render
from convergence.observe.model import load
from escape.launchers import ObserveLauncher, PolicyLauncher
from escape.oracles.base import Oracle, nonce
from escape.report import Environment
from escape.runner import SETS, Runner, _load_sets
from escape.schema import Case
from escape.score import Rate, Result

SCHEMA = "convergence.fdr/1"
JUDGED = (Result.PASS, Result.FALSE_DENIAL)


@dataclass(slots=True)
class Row:
    id: str
    observed: str  # the control's result while observed (must be "pass")
    observed_evidence: str
    rules: int  # rules in the generated policy
    warnings: int
    same_input: str
    same_input_evidence: str
    varied_input: str
    varied_input_evidence: str


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _hook(variant: str, port: int, secret: str) -> Any:
    def hook(oracle: Oracle) -> None:
        oracle.variant = variant
        oracle.fixed_port = port
        oracle.fixed_secret = secret

    return hook


def _rate(results: list[str]) -> Rate:
    judged = [r for r in results if r in JUDGED]
    return Rate(sum(r == Result.FALSE_DENIAL for r in judged), len(judged))


def _rate_json(rate: Rate) -> dict[str, Any]:
    interval = rate.interval
    return {
        "numerator": rate.numerator,
        "denominator": rate.denominator,
        "value": rate.value,
        "wilson_95": list(interval) if interval else None,
        "text": rate.describe(),
    }


def measure(path: Path, case: Case, work: Path, policies: Path | None) -> Row:
    root = work / case.id
    observation = work / f"{case.id}.observation.json"
    policy = ((policies or work) / f"{case.id}.yaml").resolve()
    port_a = _free_port()
    secret_a = nonce()

    def runner(launcher: Any, variant: str, port: int, secret: str) -> Runner:
        return Runner(
            launcher,
            subreaper=False,
            case_root=lambda _case: root,
            oracle_hook=_hook(variant, port, secret),
        )

    observed = runner(ObserveLauncher(observation), "A", port_a, secret_a).run_case(
        path, case, "controls"
    )
    row = Row(case.id, observed.result.value, observed.evidence, 0, 0, "n/a", "", "n/a", "")
    if observed.result is not Result.PASS or not observation.exists():
        return row
    generated = generate(load(observation))
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text(render(generated))
    row.rules = len(generated.reasons)
    row.warnings = len(generated.warnings)

    same = runner(PolicyLauncher(policy), "A", port_a, secret_a).run_case(path, case, "controls")
    row.same_input, row.same_input_evidence = same.result.value, same.evidence
    varied = runner(PolicyLauncher(policy), "B", _free_port(), nonce()).run_case(
        path, case, "controls"
    )
    row.varied_input, row.varied_input_evidence = varied.result.value, varied.evidence
    return row


def render_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    lines = [
        "# False-denial rates of generated policies",
        "",
        f"- kernel: {env['kernel']} ({env['arch']}), {env['os']}, "
        f"Landlock ABI {env['landlock_abi']}",
        f"- commit: `{env['commit']}`, convergence {env['convergence_version']}",
        "",
        "Each control was observed once with input A, a policy was generated from that "
        "observation, and the control was then run under it with input A and with input B.",
        "",
        "| Rate | Value |",
        "|---|---|",
        f"| same-input false-denial rate | {report['same_input']['text']} |",
        f"| varied-input false-denial rate | {report['varied_input']['text']} |",
        "",
        "| Control | Observed | Rules | Same input | Varied input | Evidence (varied) |",
        "|---|---|---:|---|---|---|",
    ]
    for row in report["controls"]:
        evidence = row["varied_input_evidence"].replace("|", "\\|")[:160]
        lines.append(
            f"| `{row['id']}` | {row['observed']} | {row['rules']} | {row['same_input']} | "
            f"{row['varied_input']} | {evidence} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m escape.fdr", description=__doc__)
    parser.add_argument("--case", action="append", metavar="ID", help="only these controls")
    parser.add_argument("--json", metavar="PATH")
    parser.add_argument("--markdown", metavar="PATH")
    parser.add_argument("--policies", metavar="DIR", help="keep the generated policies here")
    args = parser.parse_args(argv)

    cases = [(p, c) for _, p, c in _load_sets(["controls"]) if not args.case or c.id in args.case]
    if not cases:
        sys.stderr.write(f"no controls selected from {SETS['controls']}\n")
        return 2
    policies = Path(args.policies).resolve() if args.policies else None  # runs start elsewhere
    rows: list[Row] = []
    with tempfile.TemporaryDirectory(prefix="convergence-fdr-") as tmp:
        for index, (path, case) in enumerate(cases, 1):
            row = measure(path, case, Path(tmp), policies)
            rows.append(row)
            sys.stdout.write(
                f"[{index}/{len(cases)}] {case.id}: observed {row.observed}; same input "
                f"{row.same_input}; varied input {row.varied_input}\n"
            )
    abi = Runner(ObserveLauncher(Path("/dev/null")), subreaper=False).abi
    environment = Environment.collect("generated-policy", abi)
    same, varied = _rate([r.same_input for r in rows]), _rate([r.varied_input for r in rows])
    report = {
        "schema": SCHEMA,
        "environment": asdict(environment),
        "same_input": _rate_json(same),
        "varied_input": _rate_json(varied),
        "controls": [asdict(r) for r in rows],
    }
    sys.stdout.write(f"same-input FDR {same.describe()}; varied-input FDR {varied.describe()}\n")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n")
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(report))
    observed_ok = all(r.observed == Result.PASS for r in rows)
    return 0 if observed_ok and same.numerator == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
