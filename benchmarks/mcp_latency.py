"""Per-call latency of ``run_sandboxed`` over MCP (Phase 6), against the CLI and no sandbox.

    python benchmarks/mcp_latency.py --runs 50 --json R.json --markdown R.md

The workload is ``/usr/bin/true``, so the numbers are Convergence's own cost:
- **bare:** ``subprocess.run(["/usr/bin/true"])``, no sandbox;
- **mcp:** one ``run_sandboxed`` call in a warm stdio session. The cost is the round trip,
  a fork of the spawn helper, and sandbox setup;
- **cli:** ``convergence run`` started cold, including interpreter startup.

Phase 7 compares Convergence with other sandboxes; this only records the MCP path.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import anyio
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

TRUE = "/usr/bin/true"


def _policy() -> str:
    from escape.oracles.execution import find_loader

    execute = [os.path.realpath(TRUE)] + ([find_loader()] if find_loader() else [])
    return json.dumps(
        {
            "version": 1,
            "filesystem": {"read": ["/usr/lib", "/etc/ld.so.cache"], "execute": execute},
            "resources": {"wall_clock_seconds": 10},
        }
    )


def _summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, round(p * (len(ordered) - 1)))]

    return {
        "runs": len(samples),
        "p50_ms": round(pct(0.50) * 1000, 2),
        "p95_ms": round(pct(0.95) * 1000, 2),
        "p99_ms": round(pct(0.99) * 1000, 2),
        "mean_ms": round(statistics.fmean(samples) * 1000, 2),
        "stdev_ms": round(statistics.pstdev(samples) * 1000, 2),
    }


def bare(runs: int) -> list[float]:
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run([TRUE], check=True)  # noqa: S603 - a fixed path
        samples.append(time.perf_counter() - start)
    return samples


def cli(runs: int, policy: Path) -> list[float]:
    samples = []
    argv = [sys.executable, "-m", "convergence", "run", "--no-record", "--policy", str(policy)]
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run([*argv, "--", TRUE], check=True)  # noqa: S603 - fixed argv
        samples.append(time.perf_counter() - start)
    return samples


async def mcp(runs: int, policies: Path) -> list[float]:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "convergence", "mcp", "--policies", str(policies)]
    )
    samples = []
    async with Client(params) as client:
        await client.call_tool("run_sandboxed", {"command": [TRUE], "policy": "true"})  # warm up
        for _ in range(runs):
            start = time.perf_counter()
            result = await client.call_tool("run_sandboxed", {"command": [TRUE], "policy": "true"})
            samples.append(time.perf_counter() - start)
            if result.is_error or result.structured_content["exit_code"] != 0:
                raise RuntimeError(f"run_sandboxed failed: {result.content}")
    return samples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python benchmarks/mcp_latency.py")
    parser.add_argument("--runs", type=int, default=50)
    parser.add_argument("--json", metavar="PATH")
    parser.add_argument("--markdown", metavar="PATH")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="convergence-bench-") as tmp:
        policies = Path(tmp)
        (policies / "true.json").write_text(_policy())
        bare(5)  # warm the page cache
        results: dict[str, Any] = {
            "bare": _summary(bare(args.runs)),
            "mcp": _summary(anyio.run(mcp, args.runs, policies)),
            "cli": _summary(cli(max(10, args.runs // 2), policies / "true.json")),
        }
    uname = os.uname()
    report = {
        "schema": "convergence.mcp-latency/1",
        "workload": TRUE,
        "kernel": uname.release,
        "arch": uname.machine,
        "python": sys.version.split()[0],
        "cpus": os.cpu_count(),
        "results": results,
    }
    for name, row in results.items():
        sys.stdout.write(f"{name:5} p50 {row['p50_ms']:8.2f} ms   p95 {row['p95_ms']:8.2f} ms\n")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n")
    if args.markdown:
        lines = [
            "# Per-call latency of `run_sandboxed` over MCP",
            "",
            f"Workload `{TRUE}`; kernel {uname.release} ({uname.machine}), "
            f"{os.cpu_count()} CPUs, Python {report['python']}.",
            "",
            "| Path | Runs | p50 ms | p95 ms | p99 ms | mean ms | stdev ms |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        labels = {
            "bare": "no sandbox (`subprocess`)",
            "mcp": "`run_sandboxed`, warm MCP session",
            "cli": "`convergence run`, cold CLI",
        }
        for name, row in results.items():
            lines.append(
                f"| {labels[name]} | {row['runs']} | {row['p50_ms']} | {row['p95_ms']} | "
                f"{row['p99_ms']} | {row['mean_ms']} | {row['stdev_ms']} |"
            )
        Path(args.markdown).write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
