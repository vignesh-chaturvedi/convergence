"""Running a tool under strace to observe it (ADR 0008). This is not a sandbox.

The tool runs as strace's child, in a new session, with ``no_new_privs``, the default
resource limits, and a wall-clock timeout. It keeps the caller's environment, working
directory, and stdio, and has the caller's full access to everything else.
"""

from __future__ import annotations

import contextlib
import os
import resource
import shutil
import signal
import tempfile
import time
from pathlib import Path
from types import FrameType

from convergence.kernel._libc import PR_SET_CHILD_SUBREAPER, prctl, set_no_new_privs
from convergence.observe.model import Exit, Observation
from convergence.observe.trace import DEFAULT_EVENT_CAP, read_trace_dir
from convergence.policy.model import Resources
from convergence.runtime import child as child_mod
from convergence.runtime.plan import (
    EXIT_NOT_STARTED,
    EXIT_TIMEOUT,
    RunError,
    build_rlimits,
    count_user_tasks,
)
from convergence.runtime.record import new_run_id, now_iso
from convergence.runtime.supervisor import STOP_SIGNALS, kill_everything
from convergence.runtime.tracer import find_strace

WARNING = (
    "observe mode is NOT a sandbox: the command runs with your full access (only "
    "no_new_privs, resource limits, and a timeout apply). Observe untrusted tools only in a "
    "disposable VM."
)


class _Stopped(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def strace_argv(strace: str, directory: Path, command: list[str]) -> list[str]:
    return [
        strace,
        "-f",
        "-ff",
        "-yy",
        "-s",
        "4096",
        "-q",
        "-o",
        str(directory / "trace"),
        "--",
        *command,
    ]


def observe(
    command: list[str], *, timeout: float, cap: int = DEFAULT_EVENT_CAP
) -> tuple[Observation, int]:
    """Observe ``command``. Returns the observation and the exit code ``observe`` exits with."""
    if not command:
        raise RunError("no command given (use: convergence observe -- COMMAND ...)", 2)
    strace = find_strace()
    if strace is None:
        raise RunError("observe needs strace, which is not installed", EXIT_NOT_STARTED)
    directory = Path(tempfile.mkdtemp(prefix="convergence-observe-"))
    observation = Observation(
        id=new_run_id(),
        created_at=now_iso(),
        source="strace",
        command=list(command),
        cwd=os.getcwd(),
        home=os.environ.get("HOME") or None,
        complete=True,
        events=[],
        environment_names=sorted(os.environ),
        provenance={"tracer": strace, "kernel": os.uname().release, "arch": os.uname().machine},
    )
    defaults = Resources()
    limits = build_rlimits_for(defaults)
    nproc = count_user_tasks() + 2 + (defaults.max_processes or 64)
    argv = strace_argv(strace, directory, command)

    prctl(PR_SET_CHILD_SUBREAPER, 1)
    previous = {sig: signal.getsignal(sig) for sig in STOP_SIGNALS}

    def stop(signum: int, _frame: FrameType | None) -> None:
        raise _Stopped(signum)

    for sig in STOP_SIGNALS:
        signal.signal(sig, stop)
    started = time.monotonic()
    deadline = started + timeout
    pid = -1
    status: int | None = None
    timed_out = False
    stopped_by: int | None = None
    try:
        # See supervise(): no handler may run between the fork and the child's own setup.
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
        try:
            pid = os.fork()
        finally:
            if pid != 0:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        if pid == 0:
            try:
                os.setsid()
                child_mod.restore_signals()
                for which, value in limits:
                    resource.setrlimit(which, (value, value))
                resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
                set_no_new_privs()
                os.execv(strace, argv)  # noqa: S606 - a fixed strace argv, no shell
            except BaseException:  # noqa: S110 - reported by the exit status below
                pass
            os._exit(EXIT_NOT_STARTED)
        while True:
            done, wait_status = os.waitpid(pid, os.WNOHANG)
            if done:
                status = wait_status
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.02)
    except _Stopped as exc:
        stopped_by = exc.signum
    finally:
        for sig in STOP_SIGNALS:
            signal.signal(sig, lambda _signum, _frame: None)
        if pid > 0:
            status = kill_everything(pid).statuses.get(pid, status)
            if status is None:
                with contextlib.suppress(ChildProcessError):
                    _, status = os.waitpid(pid, 0)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    observation.duration_seconds = round(time.monotonic() - started, 3)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    observation.cpu_seconds = round(usage.ru_utime + usage.ru_stime, 3)
    observation.max_rss_kb = usage.ru_maxrss
    collector, pids = read_trace_dir(directory, cap=cap)
    shutil.rmtree(directory, ignore_errors=True)
    observation.events = collector.events
    observation.syscalls = dict(sorted(collector.syscalls.items()))
    observation.processes = pids
    if collector.truncated:
        observation.complete = False
        observation.limitations.append(f"stopped recording new events after {cap}")

    exit_code: int
    if stopped_by is not None:
        observation.exit = Exit(status="interrupted", signal=signal.Signals(stopped_by).name)
        observation.complete = False
        exit_code = 128 + stopped_by
    elif timed_out:
        observation.exit = Exit(status="timed-out")
        observation.complete = False
        observation.limitations.append(f"the command was stopped at the {timeout:g} s timeout")
        exit_code = EXIT_TIMEOUT
    elif status is not None and os.WIFSIGNALED(status):
        signum = os.WTERMSIG(status)
        observation.exit = Exit(status="signaled", signal=signal.Signals(signum).name)
        exit_code = 128 + signum
    else:
        code = os.waitstatus_to_exitcode(status) if status is not None else EXIT_NOT_STARTED
        observation.exit = Exit(status="exited", exit_code=code)
        exit_code = code
    if not pids:
        raise RunError("strace did not start the command (no trace was written)")
    return observation, exit_code


def build_rlimits_for(resources: Resources) -> list[tuple[int, int]]:
    """The default rlimits, without the core-dump limit's policy wrapper."""
    from convergence.policy.model import Policy

    return build_rlimits(Policy(version=1, resources=resources))
