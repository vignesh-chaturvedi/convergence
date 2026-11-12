"""Command-line entry point.

Subcommands are added phase by phase (see PLAN.md). Until a subcommand exists, the CLI says
so instead of pretending to do anything.

Exit codes: 0 success; 1 the check failed (invalid policy, minimum enforcement set missing);
2 usage error or not implemented yet; 3 ``explain``: some rules are not fully enforceable.
``run`` exits with the tool's own status, or 128+N if a signal N ended it, 124 if the
wall-clock limit was reached, 125 if the tool was not started, 126 if it could not be
executed, and 127 if it was not found.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from convergence import __version__

if TYPE_CHECKING:
    from convergence.runtime.record import RunRecord

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


def _explain_run(args: argparse.Namespace) -> int:
    import hashlib

    from convergence.generate.explain import (
        explain_run,
        find_record,
        load_record,
        render_text,
        to_json,
    )
    from convergence.policy.load import PolicyError, load_policy
    from convergence.runtime.record import runs_dir

    try:
        record = load_record(find_record(args.run, runs_dir()))
    except (OSError, ValueError) as exc:
        _say(str(exc))
        return EXIT_FAILED
    policy = None
    source = Path(record.policy.path)
    try:
        current = hashlib.sha256(source.read_bytes()).hexdigest()
        policy = load_policy(source)
        note = (
            f"policy {source} (unchanged since the run)"
            if current == record.policy.sha256
            else f"policy {source} CHANGED since the run; suggestions are against the current file"
        )
    except (OSError, PolicyError):
        note = f"policy {source} is no longer readable; suggestions cannot show current values"
    explanations = explain_run(record, policy)
    if args.json:
        sys.stdout.write(to_json(record, explanations) + "\n")
    else:
        sys.stdout.write(render_text(record, explanations, note))
    return EXIT_OK


def _explain(args: argparse.Namespace) -> int:
    if args.run is not None:
        return _explain_run(args)

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


def _say(message: str) -> None:
    sys.stderr.write(f"convergence: {message}\n")


def _run(args: argparse.Namespace) -> int:
    from convergence.policy.load import PolicyError, load_policy
    from convergence.runtime import record as run_record
    from convergence.runtime.plan import EXIT_NOT_STARTED, Plan, RunError, prepare
    from convergence.runtime.supervisor import Options, not_started_record, supervise

    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    policy_path = Path(args.policy)
    try:
        policy_text = policy_path.read_bytes()
    except OSError as exc:
        _say(f"{args.policy}: {exc.strerror}")
        return EXIT_NOT_STARTED
    options = Options(
        timeout=args.timeout,
        capture_only=args.json,
        keep=args.max_output,
        policy_path=str(policy_path.resolve()),
        policy_text=policy_text,
        trace=args.trace,
    )

    plan: Plan | None = None
    try:
        try:
            policy = load_policy(policy_path)
        except PolicyError as exc:
            raise RunError(
                f"{exc.source}: invalid policy", EXIT_NOT_STARTED, [str(i) for i in exc.issues]
            ) from exc
        options.policy_name = policy.name
        plan = prepare(policy, command, allow_degraded=args.allow_degraded)
        for rule in plan.degraded:
            _say(
                f"degraded ({rule.status.value}): {rule.id} {rule.rule}"
                + (f": {rule.detail}" if rule.detail else "")
            )
        record = supervise(plan, policy.resources.wall_clock_seconds, options)
    except RunError as exc:
        _say(str(exc))
        for detail in exc.details:
            sys.stderr.write(f"  {detail}\n")
        record = not_started_record(command, options, exc)
    finally:
        if plan is not None:
            plan.close()
            plan.remove_scratch()

    outcome = record.outcome
    if outcome.status == "timed-out":
        _say(f"stopped the tool at the wall-clock limit ({record.duration_seconds:.1f} s)")
    if outcome.descendants_killed:
        _say(f"killed {outcome.descendants_killed} process(es) the tool left running")
    _report_denials(record)
    if not args.no_record:
        try:
            run_record.save(record)
        except OSError as exc:
            _say(f"could not save the run record: {exc}")
    if args.json:
        sys.stdout.write(record.to_json() + "\n")
    return outcome.convergence_exit_code


def _observe(args: argparse.Namespace) -> int:
    from convergence.observe.driver import WARNING, observe
    from convergence.runtime.plan import RunError
    from convergence.runtime.record import runs_dir

    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    _say(WARNING)
    try:
        observation, code = observe(command, timeout=args.timeout)
    except RunError as exc:
        _say(str(exc))
        return exc.exit_code
    if args.out:
        target = Path(args.out)
    else:
        target = runs_dir().parent / "observations" / f"{observation.id}.json"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(observation.to_json() + "\n")
    files = sum(1 for e in observation.events if e.kind == "file")
    _say(
        f"observed {len(observation.events)} distinct events ({files} file, "
        f"{sum(1 for e in observation.events if e.kind == 'exec')} exec, "
        f"{sum(1 for e in observation.events if e.kind == 'net')} network) in "
        f"{len(observation.processes)} process(es); "
        + (
            "complete"
            if observation.complete
            else "INCOMPLETE: " + "; ".join(observation.limitations)
        )
    )
    _say(f"observation saved to {target}")
    return code


def _import_divergence(args: argparse.Namespace) -> int:
    import json

    from convergence.importers.divergence import ImportError_, import_divergence
    from convergence.observe.model import load
    from convergence.runtime.record import runs_dir

    source = Path(args.report)
    try:
        data = json.loads(source.read_text())
        baseline = load(args.baseline) if args.baseline else None
        observation = import_divergence(
            source, data, baseline=baseline, divergence_commit=args.divergence_commit
        )
    except (OSError, ValueError, ImportError_) as exc:
        _say(f"{args.report}: {exc}")
        return EXIT_FAILED
    target = (
        Path(args.out)
        if args.out
        else runs_dir().parent / "observations" / f"{observation.id}.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(observation.to_json() + "\n")
    flagged = sum(1 for e in observation.events if e.decoy or e.secret or e.blocked)
    _say(
        f"imported {len(observation.events)} events from {len(observation.command)} report(s); "
        f"{flagged} are decoys, secrets, or blocked attempts and will never be granted"
    )
    for warning in observation.warnings:
        _say(f"warning: {warning}")
    _say(f"observation (partial) saved to {target}; next: convergence generate --from {target}")
    return EXIT_OK


def _generate(args: argparse.Namespace) -> int:
    from convergence.generate.policy import generate, render
    from convergence.observe.model import load
    from convergence.policy.load import PolicyError

    try:
        observation = load(args.source)
    except (OSError, ValueError) as exc:
        _say(f"{args.source}: {exc}")
        return EXIT_FAILED
    generated = generate(observation, allow_list=args.allow_list)
    try:
        text = render(generated)
    except PolicyError as exc:  # a bug in the generator, never the user's fault
        _say("the generated policy is invalid; please report this")
        for issue in exc.issues:
            sys.stderr.write(f"  {issue}\n")
        return EXIT_FAILED
    for warning in generated.warnings:
        _say(f"warning: {warning}")
    if args.out:
        Path(args.out).write_text(text)
        _say(f"policy written to {args.out} ({len(generated.reasons)} rules, each with its reason)")
    else:
        sys.stdout.write(text)
    if args.rationale:
        Path(args.rationale).write_text(generated.rationale_json() + "\n")
    return EXIT_OK


def _report_denials(record: RunRecord) -> None:
    tracing = record.tracing
    if tracing.requested and not tracing.active:
        _say(f"--trace: no denial capture for this run ({tracing.detail or 'unknown reason'})")
    shown = [d for d in record.denials if d.mechanism != "timeout"]
    if not tracing.active or not shown:
        return
    _say(f"{record.denials_total} denied operation(s) seen; the first ones:")
    for denial in shown[:10]:
        what = " ".join(x for x in (denial.syscall, denial.target) if x)
        rule = f" ({denial.rule})" if denial.rule else ""
        sys.stderr.write(f"  {denial.mechanism}: {what} -> {denial.errno}{rule}\n")
    if record.denials_total > 10:
        sys.stderr.write("  ... all of them are in the run record\n")


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _byte_count(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="convergence",
        description=(
            "Least-privilege sandboxing for AI agent tools on Linux, with Landlock, "
            "seccomp, and resource limits. Pre-alpha."
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
            "enforceable. With --run: for each denial a traced run recorded, show the cause, "
            "the rule that decided it, the smallest policy change that would permit it, and "
            "its risk. Nothing is ever changed."
        ),
    )
    target = explain.add_mutually_exclusive_group(required=True)
    target.add_argument("--policy", help="policy file (YAML or JSON)")
    target.add_argument(
        "--run", metavar="ID", help="a run id or record file: explain its denials (see run --trace)"
    )
    explain.add_argument(
        "--assume-abi",
        type=int,
        metavar="N",
        help="assess against a hypothetical kernel with Landlock ABI N instead of this one",
    )
    explain.add_argument("--cwd", help="directory ${CWD} stands for (default: current directory)")
    explain.add_argument("--json", action="store_true", help="print the assessment as JSON")
    explain.set_defaults(handler=_explain)

    run = commands.add_parser(
        "run",
        help="run a command under a policy",
        description=(
            "Run COMMAND with the policy applied: Landlock for files and TCP/UDP ports, "
            "seccomp for system calls, no_new_privs, and resource limits. The tool gets only "
            "the environment the policy builds and no inherited descriptors beyond stdio. "
            "Refuses a policy this kernel cannot fully enforce unless --allow-degraded is "
            "given. Everything the tool starts is killed when its first process exits."
        ),
        epilog=(
            "Exit status: the tool's own, or 128+N if signal N ended it; 124 wall-clock limit; "
            "125 not started; 126 could not execute; 127 not found."
        ),
    )
    run.add_argument("--policy", required=True, help="policy file (YAML or JSON)")
    run.add_argument(
        "--allow-degraded",
        action="store_true",
        help="run even if some rules cannot be fully enforced here (they are listed)",
    )
    run.add_argument(
        "--timeout",
        type=_positive_float,
        metavar="S",
        help="stop after S seconds (never later than the policy's wall_clock_seconds)",
    )
    run.add_argument(
        "--json",
        action="store_true",
        help="capture the tool's output and print the run record as JSON instead",
    )
    run.add_argument(
        "--max-output",
        type=_byte_count,
        default=1024 * 1024,
        metavar="BYTES",
        help="bytes of each output stream kept in the run record (default: 1 MiB)",
    )
    run.add_argument("--no-record", action="store_true", help="do not save the run record")
    run.add_argument(
        "--trace",
        action="store_true",
        help=(
            "record which rule denied each failed operation, using strace (slower; strace "
            "runs outside the sandbox, see ADR 0007)"
        ),
    )
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    run.set_defaults(handler=_run)

    observe = commands.add_parser(
        "observe",
        help="record what a command does, to generate a policy (NOT a sandbox)",
        description=(
            "Run COMMAND under strace and record the files it opens, the directories it "
            "lists or changes, the programs it runs, the ports it uses, and every system call "
            "(ADR 0008). This is NOT a sandbox: the command has your full access; only "
            "no_new_privs, resource limits, and the timeout apply. Observe untrusted tools "
            "only in a disposable VM."
        ),
        epilog="Exit status: the command's own, 128+N for a signal, 124 timeout, 125 not started.",
    )
    observe.add_argument(
        "--out",
        metavar="FILE",
        help="where to write the observation (default: under ~/.local/state/convergence)",
    )
    observe.add_argument(
        "--timeout", type=_positive_float, default=60.0, metavar="S", help="default: 60"
    )
    observe.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    observe.set_defaults(handler=_observe)

    gen = commands.add_parser(
        "generate",
        help="write a minimal policy from an observation, with a reason for every rule",
        description=(
            "Write the smallest policy that permits what the observation saw (ADR 0009). "
            "Every rule cites the events that justify it. Credential locations, other "
            "processes' /proc entries, and unix-socket connections are never granted; they "
            "are reported as warnings."
        ),
    )
    gen.add_argument(
        "--from", dest="source", required=True, metavar="FILE", help="an observation file"
    )
    gen.add_argument("--out", metavar="FILE", help="write the policy here (default: stdout)")
    gen.add_argument(
        "--rationale", metavar="FILE", help="also write every rule's reason and events as JSON"
    )
    gen.add_argument(
        "--allow-list",
        action="store_true",
        help="allow only the syscalls observed (stricter, and fails on any new code path)",
    )
    gen.set_defaults(handler=_generate)

    importer = commands.add_parser(
        "import",
        help="turn another tool's report into an observation",
        description="Turn another tool's report into an observation for `generate`.",
    )
    sources = importer.add_subparsers(dest="source", metavar="<source>", required=True)
    divergence = sources.add_parser(
        "divergence",
        help="a Divergence dynamic-tier report (divergence.sandbox/1 or `scan --json`)",
        description=(
            "Import what Divergence's dynamic tier observed. The result is always partial: "
            "Divergence drops runtime noise on purpose and caps its observations. Decoys, "
            "secrets, and blocked attempts are kept but never granted. Merge a runtime "
            "baseline that Convergence observed itself (--baseline), or the generated policy "
            "will fail closed on the interpreter's own paths."
        ),
    )
    divergence.add_argument("report", help="divergence.sandbox/1 report or scan --json output")
    divergence.add_argument(
        "--baseline", metavar="OBS", help="an observation of the runtime to merge (recommended)"
    )
    divergence.add_argument("--out", metavar="FILE", help="where to write the observation")
    divergence.add_argument(
        "--divergence-commit", metavar="SHA", help="record the Divergence commit as provenance"
    )
    divergence.set_defaults(handler=_import_divergence)
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
