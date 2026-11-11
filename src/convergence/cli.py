"""Command-line entry point.

Subcommands are added phase by phase (see PLAN.md). Until a subcommand exists, the CLI says
so instead of pretending to do anything.

Exit codes: 0 success; 1 the check failed (invalid policy, minimum enforcement set missing);
2 usage error or not implemented yet; 3 ``explain``: some rules are not fully enforceable.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from convergence import __version__

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOT_ENFORCEABLE = 3


def _doctor(args: argparse.Namespace) -> int:
    from convergence.probe import run_doctor
    from convergence.probe.report import render_text

    report = run_doctor()
    sys.stdout.write(report.to_json() + "\n" if args.json else render_text(report))
    return EXIT_OK if report.minimum_met else EXIT_FAILED


def _validate(args: argparse.Namespace) -> int:
    from convergence.policy.paths import Variables
    from convergence.policy.validate import render_text, validate_file

    report = validate_file(args.policy, Variables.from_environment(args.cwd))
    sys.stdout.write(report.to_json() + "\n" if args.json else render_text(report))
    return EXIT_OK if report.valid else EXIT_FAILED


def _explain(args: argparse.Namespace) -> int:
    if args.run is not None:
        sys.stderr.write(
            "convergence explain --run is not implemented yet: denial explanations arrive with "
            "observe mode (Phase 5 in PLAN.md).\n"
        )
        return EXIT_USAGE

    from convergence.policy import enforce
    from convergence.policy.load import PolicyError, load_policy
    from convergence.policy.paths import Variables, resolve_all

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        sys.stderr.write(f"{exc.source}: invalid policy\n")
        for issue in exc.issues:
            sys.stderr.write(f"  {issue}\n")
        return EXIT_FAILED

    if args.assume_abi is not None:
        caps = enforce.Capabilities.assumed(args.assume_abi)
    else:
        from convergence.probe import run_doctor

        caps = enforce.Capabilities.from_doctor(run_doctor())

    paths = resolve_all(policy, Variables.from_environment(args.cwd))
    assessment = enforce.assess(policy, paths, caps)
    assessment.source = str(args.policy)
    sys.stdout.write(assessment.to_json() + "\n" if args.json else enforce.render_text(assessment))
    return EXIT_OK if assessment.would_run else EXIT_NOT_ENFORCEABLE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="convergence",
        description=(
            "Least-privilege sandboxing for AI agent tools on Linux. "
            "Pre-alpha: no enforcement is implemented yet."
        ),
    )
    parser.add_argument("--version", action="version", version=f"convergence {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    doctor = commands.add_parser(
        "doctor",
        help="report what this kernel can enforce, proven by live tests",
        description=(
            "Report the kernel's sandboxing features (Landlock, seccomp, no_new_privs, "
            "resource limits, ptrace) and prove each one by using it in a throwaway child "
            "process. Exits 1 if the minimum enforcement set is not available."
        ),
    )
    doctor.add_argument("--json", action="store_true", help="print the report as JSON")
    doctor.set_defaults(handler=_doctor)

    validate = commands.add_parser(
        "validate",
        help="check a policy file: schema, paths, syscall names, risky grants",
        description=(
            "Check a policy against the schema and against this host (paths exist, syscall "
            "names are known), and warn about grants that are valid but risky. Exits 1 if the "
            "policy is invalid."
        ),
    )
    validate.add_argument("policy", help="policy file (YAML or JSON)")
    validate.add_argument("--cwd", help="directory ${CWD} stands for (default: current directory)")
    validate.add_argument("--json", action="store_true", help="print the report as JSON")
    validate.set_defaults(handler=_validate)

    explain = commands.add_parser(
        "explain",
        help="show which rules of a policy this kernel can enforce",
        description=(
            "With --policy: show, rule by rule, how this kernel would enforce the policy, and "
            "which rules it cannot fully enforce. Capabilities come from the same live probes "
            "as `doctor`, unless --assume-abi is given. Exits 3 if any rule is not fully "
            "enforceable."
        ),
    )
    target = explain.add_mutually_exclusive_group(required=True)
    target.add_argument("--policy", help="policy file (YAML or JSON)")
    target.add_argument("--run", help="a run id (not implemented yet: Phase 5)")
    explain.add_argument(
        "--assume-abi",
        type=int,
        metavar="N",
        help="assess against a hypothetical kernel with Landlock ABI N instead of this one",
    )
    explain.add_argument("--cwd", help="directory ${CWD} stands for (default: current directory)")
    explain.add_argument("--json", action="store_true", help="print the assessment as JSON")
    explain.set_defaults(handler=_explain)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_OK
    result: int = handler(args)
    return result
