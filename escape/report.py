"""The escape-matrix report: JSON (authoritative) and a Markdown summary generated from it."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from convergence import __version__
from escape.score import Result, escape_rate, false_denial_rate

SCHEMA = "convergence.escape-report/1"
REPO = Path(__file__).resolve().parent.parent


@dataclass(slots=True)
class CaseResult:
    id: str
    set: str  # dev | holdout | controls
    category: str
    kind: str  # attack | control
    mechanism: str
    min_abi: int
    result: Result
    evidence: str
    elapsed: float | None = None
    exit_code: int | None = None
    signal: str | None = None
    timed_out: bool = False
    stderr_tail: str = ""


@dataclass(slots=True)
class Environment:
    timestamp: str
    commit: str
    kernel: str
    arch: str
    os: str
    landlock_abi: int | None
    python: str
    convergence_version: str
    launcher: str

    @classmethod
    def collect(cls, launcher: str, landlock_abi: int | None) -> Environment:
        try:
            git = shutil.which("git") or "/usr/bin/git"
            commit = subprocess.run(  # noqa: S603 - fixed argv
                [git, "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True
            ).stdout.strip()
            dirty = subprocess.run(  # noqa: S603 - fixed argv
                [git, "status", "--porcelain"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            if dirty:
                commit += "+uncommitted"
        except (OSError, subprocess.CalledProcessError):
            commit = "unknown"
        os_name = "unknown"
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip('"')
        except OSError:
            pass
        uname = os.uname()
        return cls(
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            commit=commit,
            kernel=uname.release,
            arch=uname.machine,
            os=os_name,
            landlock_abi=landlock_abi,
            python=platform.python_version(),
            convergence_version=__version__,
            launcher=launcher,
        )


def summarise(results: list[CaseResult]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in results:
        counts[item.result.value] = counts.get(item.result.value, 0) + 1
    attacks = [r.result for r in results if r.kind == "attack"]
    controls = [r.result for r in results if r.kind == "control"]
    summary: dict[str, Any] = {"cases": len(results), "counts": dict(sorted(counts.items()))}
    for label, rate in (
        ("escape_rate", escape_rate(attacks)),
        ("false_denial_rate", false_denial_rate(controls)),
    ):
        summary[label] = {
            "numerator": rate.numerator,
            "denominator": rate.denominator,
            "value": rate.value,
            "wilson_95": list(rate.interval) if rate.interval else None,
            "text": rate.describe(),
        }
    summary["documented_limitations"] = [
        r.id for r in results if r.result is Result.DOCUMENTED_LIMITATION
    ]
    return summary


def build(environment: Environment, results: list[CaseResult]) -> dict[str, Any]:
    by_set: dict[str, Any] = {}
    for name in sorted({r.set for r in results}):
        by_set[name] = summarise([r for r in results if r.set == name])
    return {
        "schema": SCHEMA,
        "environment": asdict(environment),
        "summary": summarise(results),
        "by_set": by_set,
        "results": [asdict(r) | {"result": r.result.value} for r in results],
    }


def render_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    lines = [
        "# Escape matrix report",
        "",
        f"- launcher: `{env['launcher']}`",
        f"- kernel: {env['kernel']} ({env['arch']}), {env['os']}, "
        f"Landlock ABI {env['landlock_abi']}",
        f"- commit: `{env['commit']}`, convergence {env['convergence_version']}, "
        f"Python {env['python']}, {env['timestamp']}",
        "",
        "| Set | Cases | Escape rate | False-denial rate | Results |",
        "|---|---:|---|---|---|",
    ]
    for name, summary in report["by_set"].items():
        counts = ", ".join(f"{k} {v}" for k, v in summary["counts"].items())
        lines.append(
            f"| {name} | {summary['cases']} | {summary['escape_rate']['text']} | "
            f"{summary['false_denial_rate']['text']} | {counts} |"
        )
    lines += ["", "| Case | Set | Kind | Result | Evidence |", "|---|---|---|---|---|"]
    for item in report["results"]:
        evidence = str(item["evidence"]).replace("|", "\\|")
        lines.append(
            f"| `{item['id']}` | {item['set']} | {item['kind']} | {item['result']} | {evidence} |"
        )
    return "\n".join(lines) + "\n"
