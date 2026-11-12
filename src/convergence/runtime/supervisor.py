"""The supervisor: start the sandboxed tool, contain it, and record the run (ADR 0006).

It is a child subreaper, so every process the tool leaves behind becomes its child. The run
ends when the tool's first process exits, when the wall-clock deadline passes, or when the
supervisor itself is told to stop. Then it kills the tool's process group, and keeps killing
and reaping its own children until none are left.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import resource
import select
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType

from convergence import __version__
from convergence.kernel._libc import PR_SET_CHILD_SUBREAPER, prctl
from convergence.runtime import child as child_mod
from convergence.runtime.child import REPORT, Step
from convergence.runtime.plan import (
    EXIT_CANNOT_EXECUTE,
    EXIT_NOT_FOUND,
    EXIT_NOT_STARTED,
    EXIT_TIMEOUT,
    Plan,
    RunError,
    count_user_tasks,
)
from convergence.runtime.record import (
    KernelInfo,
    Outcome,
    PolicyRef,
    RunRecord,
    StreamRecord,
    Usage,
    new_run_id,
    now_iso,
)

RELAY_THREADS = 2  # stdout and stderr; they count towards RLIMIT_NPROC like any task
DEFAULT_KEEP = 1024 * 1024  # bytes of each stream kept in the run record
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class _Stopped(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class Relay(threading.Thread):
    """Drain one of the tool's output pipes: keep the head, pass everything through."""

    def __init__(self, fd: int, sink: int | None, keep: int) -> None:
        super().__init__(daemon=True)
        self.fd = fd
        self.sink = sink
        self.keep = keep
        self.kept = bytearray()
        self.total = 0

    def run(self) -> None:
        try:
            while chunk := os.read(self.fd, 65536):
                self.total += len(chunk)
                room = self.keep - len(self.kept)
                if room > 0:
                    self.kept += chunk[:room]
                if self.sink is not None:
                    try:
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(self.sink, view) :]
                    except OSError:
                        self.sink = None  # the reader went away; keep draining the tool
        except OSError:
            pass
        finally:
            os.close(self.fd)

    def record(self, passed_through: bool) -> StreamRecord:
        return StreamRecord(
            total_bytes=self.total,
            kept=bytes(self.kept).decode(errors="replace"),
            truncated=self.total > len(self.kept),
            passed_through=passed_through,
        )


def own_children() -> list[int]:
    """Direct children of this process, including orphans re-parented to it."""
    found: set[int] = set()
    try:
        for tid in os.listdir("/proc/self/task"):
            text = Path(f"/proc/self/task/{tid}/children").read_text()
            found.update(int(pid) for pid in text.split())
        return sorted(found)
    except OSError:
        pass  # no CONFIG_PROC_CHILDREN: scan every process's parent instead
    me = os.getpid()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            stat_line = Path(entry.path, "stat").read_text()
        except OSError:
            continue
        fields = stat_line[stat_line.rfind(")") + 2 :].split()
        if int(fields[1]) == me:
            found.add(int(entry.name))
    return sorted(found)


def kill_everything(pgid: int) -> int:
    """Kill the tool's process group and every child of this process. Returns how many died.

    Only this process's own children are signalled by pid, and a child's pid cannot be
    reused before it is reaped, so nothing outside the run can be hit.
    """
    killed = 0
    for _ in range(10_000):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        children = own_children()
        if not children:
            break
        for pid in children:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        for pid in children:
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
                killed += 1
    return killed


def _wait_for_exit(pid: int, deadline: float) -> bool:
    """Block until ``pid`` exits (True) or the deadline passes (False)."""
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        pidfd = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if pidfd is not None:
                ready, _, _ = select.select([pidfd], [], [], remaining)
                if ready:
                    return True
            else:
                if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                    return True
                time.sleep(min(0.01, remaining))
    finally:
        if pidfd is not None:
            os.close(pidfd)


def _read_report(fd: int, deadline: float) -> bytes:
    """Read the child's report pipe until it closes: on exec, or after a failure."""
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            break
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
    return bytes(data)


def _start_failure(report: bytes) -> RunError:
    step_value, err = REPORT.unpack_from(report)
    message = report[REPORT.size :].decode(errors="replace")
    try:
        step = Step(step_value).name.lower().replace("_", "-")
    except ValueError:
        step = f"step {step_value}"
    reason = message or (os.strerror(err) if err else "unknown error")
    if step_value == Step.EXEC:
        if err == 2:  # ENOENT: the file, its interpreter, or its loader is missing
            return RunError(f"could not execute the tool: {reason}", EXIT_NOT_FOUND)
        hint = ""
        if err in (1, 13):  # EPERM, EACCES
            hint = (
                " (is the executable, its #! interpreter, and its dynamic loader granted in "
                "filesystem.execute?)"
            )
        return RunError(f"could not execute the tool: {reason}{hint}", EXIT_CANNOT_EXECUTE)
    return RunError(f"could not set up the sandbox at the {step} step: {reason}")


@dataclass(slots=True)
class Options:
    timeout: float | None = None  # seconds; never longer than the policy's wall clock
    capture_only: bool = False  # --json: keep output for the record, do not pass it through
    keep: int = DEFAULT_KEEP
    policy_path: str = ""
    policy_text: bytes = b""
    policy_name: str | None = None


def _base_record(plan: Plan | None, argv: list[str], options: Options) -> RunRecord:
    uname = os.uname()
    return RunRecord(
        id=new_run_id(),
        convergence_version=__version__,
        started_at=now_iso(),
        command=list(argv),
        cwd=os.getcwd(),
        policy=PolicyRef(
            path=options.policy_path,
            sha256=hashlib.sha256(options.policy_text).hexdigest(),
            name=options.policy_name,
        ),
        kernel=KernelInfo(
            release=uname.release,
            machine=uname.machine,
            landlock_abi=plan.landlock_abi if plan else None,
        ),
        outcome=Outcome(status="not-started", convergence_exit_code=EXIT_NOT_STARTED),
    )


def not_started_record(argv: list[str], options: Options, error: RunError) -> RunRecord:
    record = _base_record(None, argv, options)
    record.ended_at = record.started_at
    record.outcome = Outcome(
        status="not-started", convergence_exit_code=error.exit_code, error=str(error)
    )
    return record


def supervise(plan: Plan, wall_clock_seconds: int, options: Options) -> RunRecord:
    """Run the plan to completion. Always returns a record; never leaves a process behind."""
    record = _base_record(plan, plan.argv, options)
    record.executable = plan.executable
    record.enforcement = {
        "landlock": plan.landlock.summary() if plan.landlock else None,
        "seccomp": plan.programs.instructions if plan.programs else None,
        "seccomp_skipped": plan.programs.skipped if plan.programs else [],
        "no_new_privs": True,
        "rlimits": {resource_name(which): value for which, value in plan.rlimits},
    }
    record.degraded = [
        {"id": r.id, "rule": r.rule, "status": r.status.value, "detail": r.detail}
        for r in plan.degraded
    ]
    limit = float(wall_clock_seconds)
    if options.timeout is not None:
        limit = min(limit, options.timeout)
    started = time.monotonic()
    deadline = started + limit

    if threading.active_count() != 1:
        raise RunError("the supervisor must be single-threaded when it forks (ADR 0006)")
    prctl(PR_SET_CHILD_SUBREAPER, 1)

    report_r, report_w = os.pipe2(os.O_CLOEXEC)
    out_r, out_w = os.pipe2(os.O_CLOEXEC)
    err_r, err_w = os.pipe2(os.O_CLOEXEC)
    stdin_fd = 0
    devnull: int | None = None
    try:
        os.fstat(0)
    except OSError:
        devnull = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        stdin_fd = devnull

    setup = child_mod.prepare_child(
        executable=plan.executable,
        argv=plan.argv,
        env=plan.env,
        cwd=plan.cwd,
        landlock=plan.landlock,
        programs=(
            [plan.programs.baseline]
            + ([plan.programs.allow_list] if plan.programs and plan.programs.allow_list else [])
            if plan.programs
            else []
        ),
        rlimits=plan.rlimits,
        stdin_fd=stdin_fd,
        stdout_fd=out_w,
        stderr_fd=err_w,
        report_fd=report_w,
    )
    if plan.max_processes is not None:
        nproc = count_user_tasks() + 1 + RELAY_THREADS + plan.max_processes
        _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        if hard != resource.RLIM_INFINITY:
            nproc = min(nproc, hard)
        child_mod.set_nproc(setup, resource.RLIMIT_NPROC, nproc)
        record.enforcement["rlimits"][resource_name(resource.RLIMIT_NPROC)] = nproc  # type: ignore[index]

    previous = {sig: signal.getsignal(sig) for sig in STOP_SIGNALS}

    def stop(signum: int, _frame: FrameType | None) -> None:
        raise _Stopped(signum)

    for sig in STOP_SIGNALS:
        signal.signal(sig, stop)

    pid = -1
    relays: list[Relay] = []
    timed_out = False
    stopped_by: int | None = None
    status: int | None = None
    try:
        pid = os.fork()
        if pid == 0:
            child_mod.run_child(setup)  # never returns
        for fd in (report_w, out_w, err_w):
            os.close(fd)
        report = _read_report(report_r, deadline)
        os.close(report_r)
        if report:
            os.waitpid(pid, 0)
            raise _start_failure(report)

        sink_out = None if options.capture_only else 1
        sink_err = None if options.capture_only else 2
        relays = [Relay(out_r, sink_out, options.keep), Relay(err_r, sink_err, options.keep)]
        for relay in relays:
            relay.start()

        if _wait_for_exit(pid, deadline):
            _, status, _ = os.wait4(pid, 0)
        else:
            timed_out = True
    except _Stopped as exc:
        stopped_by = exc.signum
    finally:
        # A second signal must not interrupt the cleanup: note it and carry on.
        for sig in STOP_SIGNALS:
            signal.signal(sig, lambda _signum, _frame: None)
        if pid > 0:
            descendants = kill_everything(pid)
            if status is None:
                with contextlib.suppress(ChildProcessError):
                    _, status, _ = os.wait4(pid, 0)
        else:
            descendants = 0
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for relay in relays:
            relay.join(timeout=5)
        if not relays:
            for fd in (out_r, err_r):
                with contextlib.suppress(OSError):
                    os.close(fd)
        if devnull is not None:
            os.close(devnull)

    record.ended_at = now_iso()
    record.duration_seconds = round(time.monotonic() - started, 3)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    record.usage = Usage(
        user_cpu_seconds=round(usage.ru_utime, 3),
        system_cpu_seconds=round(usage.ru_stime, 3),
        max_rss_kb=usage.ru_maxrss,
    )
    if relays:
        record.stdout = relays[0].record(passed_through=not options.capture_only)
        record.stderr = relays[1].record(passed_through=not options.capture_only)
    # The first process exited before the run was stopped: its own status is the result.
    killed = descendants - (1 if (timed_out or stopped_by is not None) else 0)
    outcome = Outcome(status="exited", convergence_exit_code=0, descendants_killed=max(killed, 0))
    if stopped_by is not None:
        outcome.status = "interrupted"
        outcome.signal = signal.Signals(stopped_by).name
        outcome.convergence_exit_code = 128 + stopped_by
    elif timed_out:
        outcome.status = "timed-out"
        outcome.convergence_exit_code = EXIT_TIMEOUT
    elif status is not None and os.WIFSIGNALED(status):
        signum = os.WTERMSIG(status)
        outcome.status = "signaled"
        outcome.signal = signal.Signals(signum).name
        outcome.convergence_exit_code = 128 + signum
    elif status is not None:
        outcome.exit_code = os.waitstatus_to_exitcode(status)
        outcome.convergence_exit_code = outcome.exit_code
    record.outcome = outcome
    return record


def resource_name(which: int) -> str:
    for name in dir(resource):
        if name.startswith("RLIMIT_") and getattr(resource, name) == which:
            return name
    return str(which)
