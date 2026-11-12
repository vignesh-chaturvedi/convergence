"""The supervisor: start the sandboxed tool, contain it, and record the run (ADR 0006).

It is a child subreaper, so every process the tool leaves behind becomes its descendant.
The run ends when the tool's first process exits, when the wall-clock deadline passes, or
when the supervisor itself is told to stop. Then it kills the tool's process group and every
descendant, and reaps them only once all are dead (``kill_everything``). If it cannot kill
everything in time, the record says how many processes are still running.
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
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import FrameType

from convergence import __version__
from convergence.kernel._libc import PR_SET_CHILD_SUBREAPER, prctl
from convergence.runtime import child as child_mod
from convergence.runtime.child import REPORT, Step
from convergence.runtime.denials import read_trace
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
    Denial,
    KernelInfo,
    Outcome,
    PolicyRef,
    RunRecord,
    StreamRecord,
    Tracing,
    Usage,
    new_run_id,
    now_iso,
)
from convergence.runtime.tracer import Tracer

RELAY_THREADS = 2  # stdout and stderr; they count towards RLIMIT_NPROC like any task
DEFAULT_KEEP = 1024 * 1024  # bytes of each stream kept in the run record
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
KILL_SECONDS = 10.0  # how long the final sweep keeps killing before it gives up
REAP_SECONDS = 5.0  # how long it then waits for killed processes to finish exiting
SWEEP_PAUSE = 0.0005  # between sweeps: time for the kernel to deliver the signals
SWEEP_DEPTH = 128  # /proc directories held open at once while walking the process tree


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


@dataclass(slots=True)
class Cleanup:
    """What the final sweep did."""

    killed: set[int] = field(default_factory=set)  # pids found still running, and killed
    left_running: int = 0  # still running when the sweep gave up; 0 means everything is gone
    statuses: dict[int, int] = field(default_factory=dict)  # wait status of each child reaped


@cache
def _children_files() -> bool:
    """Whether this kernel lists children in /proc (CONFIG_PROC_CHILDREN)."""
    return os.path.exists(f"/proc/self/task/{threading.get_native_id()}/children")


def _read_at(dirfd: int, name: str) -> str | None:
    """The contents of ``name`` beneath an open /proc directory, or None if it is gone."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dirfd)
    except OSError:
        return None
    try:
        data = bytearray()
        while chunk := os.read(fd, 65536):
            data += chunk
        return data.decode(errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _state_and_parent(dirfd: int) -> tuple[str, int] | None:
    """``(state, parent pid)`` of the process behind ``dirfd``, or None once it is reaped."""
    text = _read_at(dirfd, "stat")
    if not text:
        return None
    fields = text[text.rfind(")") + 2 :].split()  # the name may itself contain ") "
    if len(fields) < 2:
        return None
    return fields[0], int(fields[1])


def _threads(dirfd: int) -> list[str]:
    try:
        fd = os.open("task", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dirfd)
    except OSError:
        return []
    try:
        return os.listdir(fd)
    except OSError:
        return []
    finally:
        os.close(fd)


def _children(dirfd: int, threads: list[str]) -> list[int]:
    """Children of every thread of the process behind ``dirfd``."""
    found: list[int] = []
    for tid in threads:
        text = _read_at(dirfd, f"task/{tid}/children")
        if text:
            found += [int(pid) for pid in text.split()]
    return found


def _children_by_parent() -> dict[int, list[int]]:
    """Without CONFIG_PROC_CHILDREN: every process's children, from one scan of /proc."""
    children: dict[int, list[int]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            stat_line = Path(entry.path, "stat").read_text()
        except OSError:
            continue
        fields = stat_line[stat_line.rfind(")") + 2 :].split()
        if len(fields) >= 2:
            children.setdefault(int(fields[1]), []).append(int(entry.name))
    return children


def _open_proc(pid: int | str) -> int | None:
    try:
        return os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return None


def own_children() -> list[int]:
    """Direct children of this process, including orphans re-parented to it."""
    root = _open_proc("self")
    if root is None:
        return []
    try:
        if _children_files():
            return sorted(set(_children(root, _threads(root))))
        return sorted(_children_by_parent().get(os.getpid(), []))
    finally:
        os.close(root)


def _sweep(exclude: frozenset[int], killed: set[int]) -> int:
    """Send SIGKILL to every running descendant, parents before children.

    Returns how many were still running. Nothing is reaped here (see ``kill_everything``).

    A pid read from /proc may have been reused by the time it is used. So each process is
    opened as a /proc directory, which keeps naming that one process, and is only accepted
    while it is still a child of the process it was listed under. The signal is then sent
    through that descriptor, never by pid.
    """
    scanned = None if _children_files() else _children_by_parent()

    def children_of(pid: int, dirfd: int, threads: list[str]) -> list[int]:
        return _children(dirfd, threads) if scanned is None else scanned.get(pid, [])

    me = os.getpid()
    root = _open_proc("self")
    if root is None:
        return 0
    running = 0
    stack: list[tuple[int, int, list[int]]] = [(me, root, children_of(me, root, _threads(root)))]
    try:
        while stack:
            parent, parent_fd, pending = stack[-1]
            if not pending:
                stack.pop()
                os.close(parent_fd)
                continue
            pid = pending.pop()
            if pid in exclude:
                continue
            fd = _open_proc(pid)
            if fd is None:
                continue
            info = _state_and_parent(fd)
            if (
                info is None
                or info[1] != parent
                or (parent != me and _state_and_parent(parent_fd) is None)
            ):
                os.close(fd)
                continue
            threads = _threads(fd)
            # A zombie leader with live threads is still a running process.
            if info[0] not in ("Z", "X") or len(threads) > 1:
                running += 1
                killed.add(pid)
                with contextlib.suppress(OSError):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            below = children_of(pid, fd, threads)
            if below and len(stack) < SWEEP_DEPTH:
                stack.append((pid, fd, below))
            else:
                # Anything deeper is re-parented to this process when its parent dies, and
                # is found by the next sweep.
                os.close(fd)
    finally:
        for _, fd, _ in stack:
            os.close(fd)
    return running


def _is_unreaped_child(pid: int) -> bool:
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except OSError:
        return False
    return True


def kill_everything(
    pgid: int, exclude: frozenset[int] = frozenset(), patience: float = KILL_SECONDS
) -> Cleanup:
    """Kill the tool's process group and every descendant of this process, then reap them.

    A tool can keep forking while it is being killed, and a process that has left the
    process group has to be signalled one at a time. Two things make the sweep end:
    - nothing is reaped until every descendant is dead. A dead process keeps counting
      against ``RLIMIT_NPROC`` until it is reaped, so every fork the tool wins uses up a
      slot that is not given back;
    - parents are signalled before their children, so a parent cannot reap a child the
      sweep has just killed and free a slot that way.

    Without ``resources.max_processes`` there is no such bound. The sweep then stops after
    ``patience`` seconds and reports what is still running in ``left_running``.

    ``exclude`` keeps the tracer alive so it can flush its output.
    """
    result = Cleanup()
    # The group id stays the tool's while its first process is unreaped; after that the
    # number could be reused for a group that has nothing to do with this run.
    leader_is_ours = _is_unreaped_child(pgid)
    give_up = time.monotonic() + patience
    while True:
        running = _sweep(exclude, result.killed)
        if leader_is_ours:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGKILL)
        if not running:
            break
        if time.monotonic() >= give_up:
            result.left_running = running
            break
        time.sleep(SWEEP_PAUSE)

    # Reap. Every dead descendant is by now a child of this process.
    reap_until = time.monotonic() + REAP_SECONDS
    while True:
        waiting = False
        for pid in own_children():
            if pid in exclude or pid in result.statuses:
                continue
            try:
                done, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            if done:
                result.statuses[pid] = status
            else:
                waiting = True
        if not waiting or result.left_running or time.monotonic() >= reap_until:
            break
        time.sleep(SWEEP_PAUSE)
    return result


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


def _read_report(fd: int, deadline: float, max_bytes: int | None = None) -> bytes:
    """Read the child's report pipe until it closes: on exec, or after a failure."""
    data = bytearray()
    while max_bytes is None or len(data) < max_bytes:
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
    trace: bool = False  # --trace: capture denials with strace (ADR 0007)


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
    """Run the plan to completion. Always returns a record.

    Every process of the run is killed before it returns. If that fails, the record's
    ``outcome.left_running`` says how many are still running.
    """
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

    tracer: Tracer | None = None
    trace_fds: tuple[int, int, int, int] | None = None  # ack_r, ack_w, go_r, go_w
    if options.trace:
        tracer, reason = Tracer.prepare()
        record.tracing = Tracing(requested=True, active=False, detail=reason)
        if tracer is not None:
            ack_r, ack_w = os.pipe2(os.O_CLOEXEC)
            go_r, go_w = os.pipe2(os.O_CLOEXEC)
            trace_fds = (ack_r, ack_w, go_r, go_w)

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
        trace_fds=(trace_fds[1], trace_fds[2]) if trace_fds else None,
    )
    if plan.max_processes is not None:
        helpers = 1 + RELAY_THREADS + (1 if tracer is not None else 0)
        nproc = count_user_tasks() + helpers + plan.max_processes
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
        # A stop signal must not be handled between the fork and the line that stores the
        # child's pid, in either process: the parent would lose track of the child, and the
        # child would carry on as a second supervisor. The child unblocks in run_child.
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
        try:
            pid = os.fork()
            if pid == 0:
                child_mod.run_child(setup)  # never returns
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        for fd in (report_w, out_w, err_w):
            os.close(fd)
        if tracer is not None and trace_fds is not None:
            _attach_tracer(tracer, pid, trace_fds, deadline, record)
            trace_fds = None
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

        # The first process is not reaped here: while it is a zombie, its pid cannot be
        # reused, so the process-group kill below cannot hit anything else.
        if not _wait_for_exit(pid, deadline):
            timed_out = True
    except _Stopped as exc:
        stopped_by = exc.signum
    finally:
        # A second signal must not interrupt the cleanup: note it and carry on.
        for sig in STOP_SIGNALS:
            signal.signal(sig, lambda _signum, _frame: None)
        if trace_fds is not None:  # the tool never got as far as the tracer
            for fd in trace_fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
        tracer_pids = frozenset({tracer.pid}) if tracer and tracer.pid else frozenset()
        cleanup = Cleanup()
        if pid > 0:
            cleanup = kill_everything(pid, exclude=tracer_pids)
            status = cleanup.statuses.get(pid, status)
            if status is None and not cleanup.left_running:
                with contextlib.suppress(ChildProcessError):
                    _, status, _ = os.wait4(pid, 0)
        if tracer is not None:
            tracer.finish()
            if record.tracing.active and plan.attribution is not None:
                record.denials, record.denials_total = read_trace(
                    tracer.directory, plan.attribution
                )
            tracer.cleanup()
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
    # The first process is not a descendant it left behind, even when the run killed it.
    outcome = Outcome(
        status="exited",
        convergence_exit_code=0,
        descendants_killed=len(cleanup.killed - {pid}),
        left_running=cleanup.left_running,
    )
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
    if timed_out:
        record.denials.append(
            Denial(pid, "", "", "timeout", "resources.wall_clock_seconds", f"{limit:g} s", "")
        )
        record.denials_total += 1
    record.outcome = outcome
    return record


def _attach_tracer(
    tracer: Tracer,
    pid: int,
    fds: tuple[int, int, int, int],
    deadline: float,
    record: RunRecord,
) -> None:
    """Start strace on the waiting tool, then release the tool, traced or not."""
    ack_r, ack_w, go_r, go_w = fds
    os.close(ack_w)
    os.close(go_r)
    try:
        ready = _read_report(ack_r, min(deadline, time.monotonic() + 5), max_bytes=1)
        if ready == b"R":
            tracer.start(pid)
            if tracer.wait_attached(pid):
                record.tracing.active = True
            else:
                record.tracing.detail = tracer.detail
                tracer.stop()
        else:
            record.tracing.detail = "the tool stopped before the tracer could attach"
    finally:
        with contextlib.suppress(OSError):
            os.write(go_w, b"G")
        os.close(go_w)
        os.close(ack_r)


def resource_name(which: int) -> str:
    for name in dir(resource):
        if name.startswith("RLIMIT_") and getattr(resource, name) == which:
            return name
    return str(which)
