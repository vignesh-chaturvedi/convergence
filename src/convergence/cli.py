"""Command-line entry point.

Subcommands are added phase by phase (see PLAN.md). Until a subcommand exists, the CLI says
so instead of pretending to do anything.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from convergence import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="convergence",
        description=(
            "Least-privilege sandboxing for AI agent tools on Linux. "
            "Pre-alpha: no enforcement is implemented yet."
        ),
    )
    parser.add_argument("--version", action="version", version=f"convergence {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
