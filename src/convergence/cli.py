"""Command-line entry point.

Subcommands are added phase by phase (see PLAN.md). Until a subcommand exists, the CLI says
so instead of pretending to do anything.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

from convergence import __version__

if TYPE_CHECKING:
    from convergence.probe.report import DoctorReport


def _doctor(args: argparse.Namespace) -> int:
    from convergence.probe import run_doctor

    report = run_doctor()
    sys.stdout.write(report.to_json() + "\n" if args.json else _render(report))
    return 0 if report.minimum_met else 1


def _render(report: DoctorReport) -> str:
    from convergence.probe.report import render_text

    return render_text(report)


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    result: int = handler(args)
    return result
