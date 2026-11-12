"""Run the escape matrix: set up each case, launch its payload, ask its oracle, score it.

usage:
    python -m escape.runner list [--set NAME ...]
    python -m escape.runner validity [--set NAME ...] [--holdout-run] [--json P] [--markdown P]
    python -m escape.runner run --launcher {unconfined,convergence} [--set NAME ...]
                                [--case ID ...] [--holdout-run] [--json P] [--markdown P]
    python -m escape.runner seal-holdout
    python -m escape.runner verify-holdout

Sets: dev, holdout, controls, all (default: dev and controls). Holdout cases never run
without --holdout-run, and every holdout run is logged to escape/holdout-runs.jsonl.

Exit status: 0 if no case failed; 1 if any case escaped, was falsely denied, was invalid,
errored, or could not run; 2 for usage or configuration problems.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from convergence.kernel import landlock as ll
from convergence.policy.load import PolicyError, parse_policy
from escape import report, seal
from escape.expand import UnknownVariable, VarValue, expand, expand_string
from escape.launchers import LAUNCHERS, ConvergenceLauncher, LaunchSpec, UnconfinedLauncher
from escape.oracles import CaseDirs, Evidence, OracleConfigError, create
from escape.oracles.base import scan_outputs
from escape.preconditions import Availability, Precondition, probe, probe_all
from escape.procs import Sampler, become_subreaper, kill_all, reap_zombie_children
from escape.report import CaseResult, Environment
from escape.schema import Case, CaseError, load_dir
from escape.score import FAILING, Result, score

REPO = Path(__file__).resolve().parent.parent
SETS = {
    "dev": REPO / "escape" / "cases" / "dev",
    "holdout": REPO / "escape" / "cases" / "holdout",
    "controls": REPO / "controls",
}
HOLDOUT_LOG = REPO / "escape" / "holdout-runs.jsonl"
LOADERS = ("/usr/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-x86-64.so.2")
STDERR_TAIL = 600


def _python() -> str:
    """The system interpreter payloads run with (not this virtualenv's)."""
    found = shutil.which("python3", path="/usr/bin:/bin")
    if found is None:
        raise RuntimeError("no system python3 in /usr/bin or /bin")
    return str(Path(found).resolve())


def _remove_tree(root: Path) -> None:
    """Remove a case directory even if the payload made parts of it unreadable."""

    def fix(func: Any, path: str, _exc: object) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRWXU)
            parent = os.path.dirname(path)
            os.chmod(parent, stat.S_IRWXU)
            func(path)

    shutil.rmtree(root, onexc=fix)


def kernel_abi() -> int | None:
    try:
        return ll.abi_version()
    except ll.LandlockUnavailable:
        return None


class Runner:
    def __init__(
        self,
        launcher: UnconfinedLauncher | ConvergenceLauncher,
        *,
        subreaper: bool = True,
        preconditions: Iterable[Precondition] = (),
    ) -> None:
        self.launcher = launcher
        self.abi = kernel_abi()
        self.python = _python()
        self._caps: Any = None
        # Probe what the selected cases need up front: some probes fork, which is only safe
        # before threads start. Anything else is probed (and cached) on first use.
        self.preconditions: dict[Precondition, Availability] = probe_all(preconditions)
        if subreaper:
            # Daemons that double-fork out of a run's session reparent here, so the persist
            # oracle can see them. Without this they would reparent to init and go unseen.
            become_subreaper()

    def _capabilities(self) -> Any:
        if self._caps is None:
            from convergence.policy.enforce import Capabilities
            from convergence.probe import run_doctor

            self._caps = Capabilities.from_doctor(run_doctor())
        return self._caps

    def _base_variables(self, dirs: CaseDirs, reached: str) -> dict[str, VarValue]:
        variables: dict[str, VarValue] = {
            "WORKDIR": str(dirs.work),
            "OUT_DIR": str(dirs.out),
            "OUT": str(dirs.out / "output.txt"),
            "PYTHON": self.python,
            "REACHED": reached,
        }
        loader = next((p for p in LOADERS if os.path.exists(p)), None)
        if loader is not None:
            variables["LOADER"] = str(Path(loader).resolve())
        return variables

    def run_case(self, path: Path, case: Case, set_name: str) -> CaseResult:
        result = CaseResult(
            id=case.id,
            set=set_name,
            category=case.category,
            kind="control" if case.is_control else "attack",
            mechanism=case.expect.mechanism,
            min_abi=case.expect.min_abi,
            result=Result.ERROR,
            evidence="",
        )
        if os.uname().machine not in case.platforms.arch:
            result.result, result.evidence = (
                Result.SKIPPED_PLATFORM,
                f"not for {os.uname().machine}",
            )
            return result
        for name in case.platforms.requires:
            if name not in self.preconditions:
                self.preconditions[name] = probe(name)
        missing = [r for r in case.platforms.requires if not self.preconditions[r].available]
        if missing:
            details = "; ".join(f"{r}: {self.preconditions[r].detail}" for r in missing)
            result.result = Result.NOT_TESTABLE
            result.evidence = (
                f"the host already prevents what this case needs ({details}), so it cannot "
                "show anything about Convergence here"
            )
            return result
        reason = self.launcher.unavailable_reason()
        if reason is not None:
            result.result, result.evidence = Result.LAUNCHER_UNAVAILABLE, reason
            return result

        root = Path(tempfile.mkdtemp(prefix="convergence-escape-"))
        oracle = None
        try:
            dirs = CaseDirs.create(root)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            oracle = create(case.oracle)
            setup = oracle.setup(dirs)
            reached_token = "convergence-reached-" + secrets.token_hex(8)
            variables = self._base_variables(dirs, reached_token) | setup.variables

            if case.payload.file is not None:
                source = path.parent / case.payload.file
                target = dirs.work / Path(case.payload.file).name
                target.write_text(str(expand_string(source.read_text(), variables, strict=False)))
                interpreter = self.python if target.suffix == ".py" else "/bin/sh"
                argv = [interpreter, str(target)]
            else:
                argv = [str(a) for a in expand(list(case.payload.argv or ()), variables)]
            stdin = (
                str(expand_string(case.payload.stdin, variables)) if case.payload.stdin else None
            )

            policy_data = expand(case.policy, variables)
            policy = parse_policy(json.dumps(policy_data), source=f"{case.id}: policy")
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy_data, indent=2))

            if isinstance(self.launcher, ConvergenceLauncher):
                from convergence.policy.enforce import assess
                from convergence.policy.paths import Variables, resolve_all

                home = os.environ.get("HOME", str(root))
                assessment = assess(
                    policy,
                    resolve_all(policy, Variables(home=home, cwd=str(dirs.work))),
                    self._capabilities(),
                )
                if not assessment.would_run:
                    blocking = ", ".join(r.id for r in assessment.blocking)
                    result.result = Result.SKIPPED_UNENFORCEABLE
                    result.evidence = f"not enforceable on this kernel: {blocking}"
                    return result

            spec = LaunchSpec(
                argv=argv,
                cwd=dirs.work,
                policy=policy,
                policy_path=policy_path,
                supervisor_env=dict(os.environ) | setup.supervisor_env,
                scratch=scratch,
                home=os.environ.get("HOME", str(root)),
                stdin=stdin,
                inherit_fds=setup.inherit_fds,
            )
            running = self.launcher.start(spec)
            sampler = Sampler(running.pid, setup.sampler, exclude=setup.exclude_pids)
            sampler.start()
            exit_info = running.wait()
            time.sleep(setup.settle_seconds)
            sampler.sample_once()
            survivors = sampler.alive_members(excluding_root=True)
            sampler.stop()
            kill_all(survivors)
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(running.pid, 9)
            output = running.output()

            evidence = Evidence(
                exit=exit_info,
                output=output,
                peaks=sampler.peaks(),
                max_concurrent=sampler.max_concurrent,
                survivors=survivors,
                overhead_processes=self.launcher.overhead_processes,
                policy=policy,
                max_keys=sampler.max_keys,
            )
            observation = oracle.check(dirs, evidence)
            reached = scan_outputs(reached_token, output, dirs.out) is not None
            result.result = score(
                is_control=case.is_control,
                launcher=self.launcher.name,
                observed=observation.observed,
                reached=reached,
                min_abi=case.expect.min_abi,
                kernel_abi=self.abi,
            )
            result.evidence = observation.evidence
            if not case.is_control and not reached:
                result.evidence += (
                    "; the payload never emitted ${REACHED}, so it may have been stopped before "
                    "its attempt (emit it, flushed, just before attempting)"
                )
            result.elapsed = round(exit_info.elapsed, 3)
            result.exit_code = exit_info.exit_code
            result.signal = exit_info.signal
            result.timed_out = exit_info.timed_out
            if result.result in FAILING:
                result.stderr_tail = output.stderr[-STDERR_TAIL:].decode(errors="replace")
        except (
            OracleConfigError,
            PolicyError,
            UnknownVariable,
            RuntimeError,
            ValueError,
            OSError,
        ) as exc:
            result.result, result.evidence = Result.ERROR, f"{type(exc).__name__}: {exc}"
        finally:
            if oracle is not None:
                oracle.teardown()
            reap_zombie_children(known=set())
            _remove_tree(root)
        return result


def _load_sets(names: list[str]) -> list[tuple[str, Path, Case]]:
    cases: list[tuple[str, Path, Case]] = []
    for name in names:
        directory = SETS[name]
        if not directory.exists():
            continue
        cases += [(name, path, case) for path, case in load_dir(directory)]
    seen: dict[str, str] = {}
    for name, _, case in cases:
        if case.id in seen:
            raise CaseError(name, f"case id {case.id!r} is used in both {seen[case.id]} and {name}")
        seen[case.id] = name
    return cases


def _expand_sets(requested: list[str] | None) -> list[str]:
    if not requested:
        return ["dev", "controls"]
    names: list[str] = []
    for name in requested:
        for item in ["dev", "holdout", "controls"] if name == "all" else [name]:
            if item not in names:
                names.append(item)
    return names


def _log_holdout_run(environment: Environment, payload: dict[str, Any]) -> None:
    summary = payload["by_set"].get("holdout", {})
    entry = {
        "timestamp": environment.timestamp,
        "commit": environment.commit,
        "kernel": environment.kernel,
        "landlock_abi": environment.landlock_abi,
        "arch": environment.arch,
        "launcher": environment.launcher,
        "counts": summary.get("counts", {}),
        "escape_rate": summary.get("escape_rate", {}).get("text"),
    }
    with HOLDOUT_LOG.open("a") as log:
        log.write(json.dumps(entry, sort_keys=True) + "\n")


def _run(args: argparse.Namespace, launcher_name: str) -> int:
    names = _expand_sets(args.set)
    if "holdout" in names:
        if not args.holdout_run:
            sys.stderr.write(
                "refusing to run holdout cases without --holdout-run. The holdout is run once per "
                "milestone and not consulted while tuning (escape/README.md).\n"
            )
            return 2
        problems = seal.verify()
        if problems:
            sys.stderr.write(
                "the holdout seal is broken:\n" + "".join(f"  {p}\n" for p in problems)
            )
            return 2
    try:
        cases = _load_sets(names)
    except CaseError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c[2].id in wanted]
        missing = wanted - {c[2].id for c in cases}
        if missing:
            sys.stderr.write(f"unknown case id(s): {', '.join(sorted(missing))}\n")
            return 2

    launcher = LAUNCHERS[launcher_name]()
    needed = {name for _, _, case in cases for name in case.platforms.requires}
    runner = Runner(launcher, subreaper=not args.no_subreaper, preconditions=sorted(needed))
    environment = Environment.collect(launcher.name, runner.abi)
    results: list[CaseResult] = []
    for index, (set_name, path, case) in enumerate(cases, 1):
        item = runner.run_case(path, case, set_name)
        results.append(item)
        sys.stderr.write(
            f"[{index}/{len(cases)}] {item.result.value:<22} {case.id}: {item.evidence}\n"
        )

    payload = report.build(environment, results)
    if "holdout" in names:
        _log_holdout_run(environment, payload)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(report.render_markdown(payload))
    summary = payload["summary"]
    sys.stdout.write(
        f"{launcher.name}: {summary['cases']} case(s); {summary['counts']}; "
        f"escape rate {summary['escape_rate']['text']}; "
        f"false-denial rate {summary['false_denial_rate']['text']}\n"
    )
    return 1 if any(r.result in FAILING for r in results) else 0


def _list(args: argparse.Namespace) -> int:
    names = _expand_sets(args.set)
    if "holdout" in names:
        sys.stderr.write(
            "listing holdout cases is not supported: they are not consulted while tuning\n"
        )
        return 2
    try:
        cases = _load_sets(names)
    except CaseError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    for set_name, _, case in cases:
        sys.stdout.write(f"{set_name:<9} {case.category:<28} {case.oracle.type:<18} {case.id}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m escape.runner", description=__doc__.split("\n\n")[0]
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_run_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--set", action="append", choices=[*SETS, "all"], help="repeatable")
        sub.add_argument("--case", action="append", metavar="ID", help="run only these case ids")
        sub.add_argument("--holdout-run", action="store_true", help="allow (and log) a holdout run")
        sub.add_argument("--json", metavar="PATH", help="write the JSON report here")
        sub.add_argument("--markdown", metavar="PATH", help="write the Markdown report here")
        sub.add_argument("--no-subreaper", action="store_true", help=argparse.SUPPRESS)

    run = commands.add_parser("run", help="run cases with a launcher")
    run.add_argument("--launcher", choices=sorted(LAUNCHERS), required=True)
    add_run_options(run)
    validity = commands.add_parser("validity", help="run cases unconfined: attacks must escape")
    add_run_options(validity)
    listing = commands.add_parser("list", help="list cases")
    listing.add_argument("--set", action="append", choices=[*SETS, "all"])
    commands.add_parser("seal-holdout", help="write escape/cases/holdout.sha256")
    commands.add_parser("verify-holdout", help="check the holdout against its seal")

    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(args, args.launcher)
    if args.command == "validity":
        return _run(args, "unconfined")
    if args.command == "list":
        return _list(args)
    if args.command == "seal-holdout":
        count = seal.seal()
        sys.stdout.write(f"sealed {count} holdout file(s) in {seal.MANIFEST.relative_to(REPO)}\n")
        return 0
    problems = seal.verify()
    for problem in problems:
        sys.stdout.write(f"{problem}\n")
    if not problems:
        sys.stdout.write("holdout matches its seal\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
