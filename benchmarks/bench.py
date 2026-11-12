"""Phase 7 benchmarks: the cost of starting a tool under Convergence and its alternatives.

The method, including what "cold" means, is fixed in ADR 0011. One command regenerates a
result; with ``--readme`` it also regenerates the README table:

    PYTHONPATH=. uv run python benchmarks/bench.py run --env lima-ubuntu-24.04-ga-aarch64 --readme
    PYTHONPATH=. uv run python benchmarks/bench.py readme   # the README table only

The JSON in benchmarks/results/ is authoritative; the Markdown is generated from it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "benchmarks" / "results"
README = REPO / "README.md"
README_SOURCE = RESULTS / "lima-ubuntu-24.04-ga-aarch64.json"
MARK_START, MARK_END = "<!-- benchmarks:start -->", "<!-- benchmarks:end -->"
SCHEMA = "convergence.bench/1"

CONFIGS = (
    "bare",
    "sudo",
    "convergence-api",
    "convergence-api-trace",
    "convergence-mcp",
    "convergence-cli",
    "bwrap",
    "docker-warm",
    "docker-cold",
)
WORKLOADS = ("true", "python", "wordcount")
IMAGE = "python:3.12-slim"
TRUE = "/usr/bin/true"
WORDCOUNT = """import collections, sys
words = collections.Counter(open(sys.argv[1]).read().split())
with open(sys.argv[2], "w") as out:
    for word, count in words.most_common(20):
        out.write(f"{word} {count}\\n")
"""


class Unavailable(Exception):
    pass


def _run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, check=True, capture_output=True, **kwargs)  # noqa: S603


def _first_line(argv: list[str]) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=30)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable ({exc})"
    text = (done.stdout or done.stderr).strip().splitlines()
    return text[0] if text else f"exit {done.returncode}"


@dataclass(slots=True)
class Work:
    root: Path
    python: str
    policy: Path
    policies: Path
    image: str | None = None  # the pinned image reference, once pulled

    def host_argv(self, workload: str) -> list[str]:
        if workload == "true":
            return [TRUE]
        if workload == "python":
            return [self.python, "-c", "pass"]
        return [self.python, "wc.py", "input.txt", "out/counts.txt"]

    @staticmethod
    def docker_argv(workload: str) -> list[str]:
        if workload == "true":
            return ["/bin/true"]
        if workload == "python":
            return ["python3", "-c", "pass"]
        return ["python3", "wc.py", "input.txt", "out/counts.txt"]


def prepare(root: Path) -> Work:
    from escape.oracles.execution import find_loader

    python = str(Path(shutil.which("python3", path="/usr/bin:/bin") or "python3").resolve())
    (root / "out").mkdir(parents=True)
    (root / "wc.py").write_text(WORDCOUNT)
    words = (f"word{i % 997} " for i in range(150_000))
    (root / "input.txt").write_text("".join(words)[: 1024 * 1024])
    execute = sorted({python, os.path.realpath(TRUE)})
    if find_loader():
        execute.append(str(find_loader()))
    policy = {
        "version": 1,
        "name": "benchmark",
        "filesystem": {
            "read": ["/usr", "/etc/ld.so.cache", str(root)],
            "write": [str(root / "out")],
            "execute": execute,
        },
        "resources": {"wall_clock_seconds": 60},
        "environment": {"set": {"PATH": "/usr/bin", "LANG": "C.UTF-8"}},
    }
    policies = root / "policies"
    policies.mkdir()
    (policies / "bench.json").write_text(json.dumps(policy))
    return Work(root, python, policies / "bench.json", policies)


# --- configurations: each returns (run_once, before_each, close) ---------------------------

Runner = tuple[Callable[[str], None], Callable[[], None] | None, Callable[[], None]]


def _nothing() -> None:
    return None


def bare(work: Work) -> Runner:
    def once(workload: str) -> None:
        _run(work.host_argv(workload), cwd=work.root)

    return once, None, _nothing


def sudo(work: Work) -> Runner:
    try:
        _run(["sudo", "-n", TRUE])
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Unavailable(f"sudo -n is not available: {exc}") from exc

    def once(_workload: str) -> None:
        _run(["sudo", "-n", TRUE])

    return once, None, _nothing


def _api(work: Work, trace: bool) -> Runner:
    from convergence.api import Sandbox
    from convergence.runtime.tracer import find_strace

    if trace and find_strace() is None:
        raise Unavailable("strace is not installed")
    sandbox = Sandbox()

    def once(workload: str) -> None:
        record = sandbox.run(work.host_argv(workload), work.policy, cwd=work.root, trace=trace)
        if record["outcome"]["exit_code"] != 0:
            raise RuntimeError(f"run failed: {record['outcome']} {record['stderr']['kept'][-300:]}")

    return once, None, sandbox.close


def convergence_api(work: Work) -> Runner:
    return _api(work, trace=False)


def convergence_api_trace(work: Work) -> Runner:
    return _api(work, trace=True)


def convergence_cli(work: Work) -> Runner:
    base = [sys.executable, "-m", "convergence", "run", "--no-record", "--policy", str(work.policy)]

    def once(workload: str) -> None:
        _run([*base, "--", *work.host_argv(workload)], cwd=work.root)

    return once, None, _nothing


def bwrap(work: Work) -> Runner:
    if shutil.which("bwrap") is None:
        raise Unavailable("bwrap is not installed")
    base = ["bwrap", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache", "--proc", "/proc",
            "--dev", "/dev", "--tmpfs", "/tmp",  # noqa: S108 - inside bwrap
            "--bind", str(work.root), str(work.root),
            "--chdir", str(work.root),
            "--unshare-all", "--die-with-parent", "--new-session"]  # fmt: skip
    if Path("/lib64").exists():
        base += ["--symlink", "usr/lib64", "/lib64"]
    probe = subprocess.run([*base, "--", TRUE], capture_output=True, text=True, check=False)  # noqa: S603
    if probe.returncode != 0:
        raise Unavailable(f"bwrap cannot run here: {probe.stderr.strip()[:200]}")

    def once(workload: str) -> None:
        _run([*base, "--", *work.host_argv(workload)])

    return once, None, _nothing


def _docker_ready(work: Work) -> list[str]:
    docker = ["sudo", "-n", "docker"]
    try:
        _run([*docker, "info"])
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Unavailable(f"docker is not available through sudo -n: {exc}") from exc
    if work.image is None:
        _run([*docker, "pull", "-q", IMAGE])
        digest = _run([*docker, "image", "inspect", "--format", "{{index .RepoDigests 0}}", IMAGE])
        work.image = digest.stdout.decode().strip()
    return docker


def _docker_once(work: Work, docker: list[str]) -> Callable[[str], None]:
    base = [*docker, "run", "--rm", "--network", "none", "-v", f"{work.root}:/work", "-w", "/work"]

    def once(workload: str) -> None:
        _run([*base, str(work.image), *work.docker_argv(workload)])

    return once


def docker_warm(work: Work) -> Runner:
    docker = _docker_ready(work)
    return _docker_once(work, docker), None, _nothing


def docker_cold(work: Work) -> Runner:
    docker = _docker_ready(work)

    def before() -> None:
        # Stop the daemon and its socket, clear systemd's start-rate counter (it refuses
        # frequent restarts), drop the page cache, then start the daemon again.
        _run(
            ["sudo", "-n", "sh", "-c",
             "systemctl stop docker.service docker.socket && "
             "systemctl reset-failed docker.service docker.socket; "
             "sync && echo 3 > /proc/sys/vm/drop_caches && systemctl start docker.service"]
        )  # fmt: skip
        for _ in range(100):
            if subprocess.run([*docker, "info"], capture_output=True, check=False).returncode == 0:  # noqa: S603
                break
            time.sleep(0.1)
        _run(["sudo", "-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"])

    return _docker_once(work, docker), before, _nothing


FACTORIES: dict[str, Callable[[Work], Runner]] = {
    "bare": bare,
    "sudo": sudo,
    "convergence-api": convergence_api,
    "convergence-api-trace": convergence_api_trace,
    "convergence-cli": convergence_cli,
    "bwrap": bwrap,
    "docker-warm": docker_warm,
    "docker-cold": docker_cold,
}


# --- measurement --------------------------------------------------------------------------


def summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def rank(p: float) -> float:  # nearest rank: the smallest value >= p of the samples
        return ordered[max(0, math.ceil(p * len(ordered)) - 1)]

    return {
        "runs": len(samples),
        "p50_ms": round(rank(0.50) * 1000, 2),
        "p95_ms": round(rank(0.95) * 1000, 2),
        "p99_ms": round(rank(0.99) * 1000, 2),
        "mean_ms": round(statistics.fmean(samples) * 1000, 2),
        "stdev_ms": round(statistics.pstdev(samples) * 1000, 2),
    }


def measure(runner: Runner, workload: str, runs: int, warmup: int) -> dict[str, float]:
    once, before, _ = runner
    for _ in range(warmup):
        once(workload)
    samples = []
    for _ in range(runs):
        if before is not None:
            before()
        start = time.perf_counter()
        once(workload)
        samples.append(time.perf_counter() - start)
    return summary(samples)


def measure_mcp(work: Work, workloads: list[str], runs: int, warmup: int) -> dict[str, Any]:
    import anyio
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters

    async def main() -> dict[str, Any]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "convergence", "mcp", "--policies", str(work.policies)],
            cwd=str(work.root),
        )
        results: dict[str, Any] = {}
        async with Client(params) as client:
            for workload in workloads:
                arguments = {
                    "command": work.host_argv(workload),
                    "policy": "bench",
                    "cwd": str(work.root),
                }
                samples = []
                for index in range(warmup + runs):
                    start = time.perf_counter()
                    result = await client.call_tool("run_sandboxed", arguments)
                    elapsed = time.perf_counter() - start
                    content = result.structured_content or {}
                    if result.is_error or content.get("exit_code") != 0:
                        raise RuntimeError(f"run_sandboxed failed: {result.content}")
                    if index >= warmup:
                        samples.append(elapsed)
                results[workload] = summary(samples)
        return results

    return dict(anyio.run(main))


def environment(label: str) -> dict[str, Any]:
    from convergence import __version__

    cpu = "unknown"
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.lower().startswith(("model name", "hardware")):
            cpu = line.split(":", 1)[1].strip()
            break
    if cpu == "unknown":
        cpu = _first_line(["sh", "-c", "lscpu | grep -m1 'Model name' | cut -d: -f2"]).strip()
    memory = next(
        (line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
         if line.startswith("MemTotal:")), "0")  # fmt: skip
    release = Path("/etc/os-release").read_text().splitlines()
    os_name = next(
        (line.split("=", 1)[1].strip('"') for line in release if line.startswith("PRETTY_NAME=")),
        "unknown",
    )
    commit = _first_line(["git", "-C", str(REPO), "rev-parse", "HEAD"])
    dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain"],  # noqa: S603, S607
                           capture_output=True, text=True, check=False).stdout.strip()  # fmt: skip
    return {
        "label": label,
        "cpu": cpu or "unknown",
        "cpus": os.cpu_count(),
        "memory_mib": int(memory) // 1024,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os": os_name,
        "python": platform.python_version(),
        "convergence": __version__,
        "commit": commit + ("+uncommitted" if dirty else ""),
        "strace": _first_line(["strace", "-V"]),
        "bwrap": _first_line(["bwrap", "--version"]),
        "docker": _first_line(
            ["sudo", "-n", "docker", "version", "--format", "{{.Server.Version}}"]
        ),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# --- reports ------------------------------------------------------------------------------

LABELS = {
    "bare": "no sandbox (`subprocess`)",
    "sudo": "`sudo -n true` (inside every Docker row)",
    "convergence-api": "Convergence, library API, warm",
    "convergence-api-trace": "Convergence, library API, warm, `--trace`",
    "convergence-mcp": "Convergence, one MCP `run_sandboxed` call",
    "convergence-cli": "Convergence CLI, cold process",
    "bwrap": "bubblewrap",
    "docker-warm": "`docker run --rm`, warm",
    "docker-cold": "`docker run --rm`, cold daemon and cache",
}


def _cell(row: dict[str, Any] | None) -> str:
    if row is None:
        return "-"
    if "unavailable" in row:
        return "n/a"
    return f"{row['p50_ms']:g} ({row['p95_ms']:g})"


def table(report: dict[str, Any]) -> str:
    lines = [
        "| Configuration | " + " | ".join(f"`{w}` p50 (p95) ms" for w in WORKLOADS) + " |",
        "|---|" + "---:|" * len(WORKLOADS),
    ]
    for config in CONFIGS:
        rows = report["results"].get(config)
        if rows is None:
            continue
        lines.append(
            f"| {LABELS[config]} | " + " | ".join(_cell(rows.get(w)) for w in WORKLOADS) + " |"
        )
    notes = sorted({row["unavailable"] for rows in report["results"].values()
                    for row in rows.values() if "unavailable" in row})  # fmt: skip
    for note in notes:
        lines.append(f"\nn/a: {note}")
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    env, method = report["environment"], report["method"]
    lines = [
        "# Benchmarks",
        "",
        f"- **{env['label']}**: {env['cpu']}, {env['cpus']} CPUs, {env['memory_mib']} MiB; "
        f"{env['os']}, kernel {env['kernel']} ({env['arch']}); Python {env['python']}",
        f"- convergence {env['convergence']} at `{env['commit']}`; {env['strace']}; "
        f"{env['bwrap']}; Docker {env['docker']}; image `{report.get('image') or 'not used'}`",
        f"- {method['runs']} measured runs per cell after {method['warmup']} warm-up runs "
        f"(docker-cold: {method['cold_runs']}, no warm-up); method in "
        "[ADR 0011](../../docs/adr/0011-benchmark-method.md)",
        "",
        table(report),
        "",
        "| Configuration | Workload | Runs | p50 | p95 | p99 | mean | stdev |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for config, rows in report["results"].items():
        for workload, row in rows.items():
            if "unavailable" in row:
                continue
            lines.append(
                f"| {config} | {workload} | {row['runs']} | {row['p50_ms']} | {row['p95_ms']} | "
                f"{row['p99_ms']} | {row['mean_ms']} | {row['stdev_ms']} |"
            )
    return "\n".join(lines) + "\n"


def readme_section(report: dict[str, Any]) -> str:
    env = report["environment"]
    return (
        f"{MARK_START}\n"
        f"Generated from [`{README_SOURCE.relative_to(REPO)}`]"
        f"({README_SOURCE.relative_to(REPO)}) by `benchmarks/bench.py`: {env['label']}, "
        f"{env['cpus']} CPUs, kernel {env['kernel']} ({env['arch']}). Wall-clock time to start "
        "the workload and see it exit; p50 (p95) in milliseconds over "
        f"{report['method']['runs']} runs.\n\n{table(report)}\n{MARK_END}"
    )


def update_readme(source: Path = README_SOURCE) -> None:
    text = README.read_text()
    start, end = text.index(MARK_START), text.index(MARK_END) + len(MARK_END)
    section = readme_section(json.loads(source.read_text()))
    README.write_text(text[:start] + section + text[end:])


# --- command line -------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    configs = args.configs or list(CONFIGS)
    workloads = args.workloads or list(WORKLOADS)
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="convergence-bench-") as tmp:
        work = prepare(Path(tmp))
        for config in configs:
            results[config] = {}
            sys.stdout.write(f"{config}:\n")
            if config == "convergence-mcp":
                try:
                    results[config] = measure_mcp(work, workloads, args.runs, args.warmup)
                    for workload, row in results[config].items():
                        sys.stdout.write(f"  {workload}: p50 {row['p50_ms']} ms\n")
                except ImportError as exc:
                    results[config] = {
                        w: {"unavailable": f"mcp SDK missing ({exc})"} for w in workloads
                    }
                continue
            try:
                runner = FACTORIES[config](work)
            except Unavailable as exc:
                results[config] = {w: {"unavailable": str(exc)} for w in workloads}
                sys.stdout.write(f"  unavailable: {exc}\n")
                continue
            try:
                for workload in workloads:
                    cold = config == "docker-cold"
                    row = measure(runner, workload, args.cold_runs if cold else args.runs,
                                  0 if cold else args.warmup)  # fmt: skip
                    results[config][workload] = row
                    sys.stdout.write(
                        f"  {workload}: p50 {row['p50_ms']} ms, p95 {row['p95_ms']} ms\n"
                    )
                    sys.stdout.flush()
            finally:
                runner[2]()
        report = {
            "schema": SCHEMA,
            "environment": environment(args.label or args.env),
            "image": work.image,
            "method": {"runs": args.runs, "warmup": args.warmup, "cold_runs": args.cold_runs},
            "results": results,
        }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{args.env}.json").write_text(json.dumps(report, indent=2) + "\n")
    (RESULTS / f"{args.env}.md").write_text(render_markdown(report))
    if args.readme:
        update_readme(RESULTS / f"{args.env}.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks/bench.py", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="measure, and write results/<env>.json and .md")
    run_parser.add_argument(
        "--env", required=True, help="result name, e.g. lima-ubuntu-24.04-ga-aarch64"
    )
    run_parser.add_argument("--label", help="environment label (default: --env)")
    run_parser.add_argument("--runs", type=int, default=200)
    run_parser.add_argument("--warmup", type=int, default=10)
    run_parser.add_argument("--cold-runs", type=int, default=200)
    run_parser.add_argument("--configs", nargs="*", choices=CONFIGS)
    run_parser.add_argument("--workloads", nargs="*", choices=WORKLOADS)
    run_parser.add_argument(
        "--readme", action="store_true", help="also regenerate the README table"
    )
    commands.add_parser("readme", help=f"regenerate the README table from {README_SOURCE.name}")
    args = parser.parse_args(argv)
    if args.command == "readme":
        update_readme()
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
