"""The forked child: apply the sandbox, then exec the tool (ADR 0006).

Everything here runs in a single-threaded copy of the supervisor. The order is fixed:

1. new session, default signal handling, stdio, working directory;
2. die with the supervisor (``PR_SET_PDEATHSIG``), then ``no_new_privs``;
3. the ``/proc/self`` rules, then ``landlock_restrict_self``;
4. every descriptor above 2 becomes close-on-exec;
5. rlimits, seccomp, ``execve``, through objects prepared before the fork.

From step 5 on, nothing may allocate: ``RLIMIT_DATA`` and ``RLIMIT_AS`` are usually below
what the forked interpreter already uses, so any new allocation would fail. A failure at any
step is written to the report pipe as ``(step, errno)`` plus, before step 5, a message; the
child then exits without running the tool.
"""

from __future__ import annotations

import contextlib
import ctypes
import enum
import gc
import os
import signal
import stat
import struct
from dataclasses import dataclass, field
from typing import NoReturn

from convergence.kernel import seccomp as sc
from convergence.kernel._libc import (
    CLOSE_RANGE_CLOEXEC,
    PR_SET_PDEATHSIG,
    PR_SET_SECCOMP,
    SECCOMP_MODE_FILTER,
    SYS_CLOSE_RANGE,
    libc,
    prctl,
    set_no_new_privs,
    syscall,
)
from convergence.policy.rights import rights_for
from convergence.runtime.plan import LandlockPlan

EXIT_SETUP_FAILED = 125
PR_SET_PTRACER = 0x59616D61  # Yama: name a process (and its descendants) as allowed tracer
REPORT = struct.Struct("=ii")  # step, errno


class Step(enum.IntEnum):
    SESSION = 1
    SIGNALS = 2
    STDIO = 3
    CHDIR = 4
    PDEATHSIG = 5
    NO_NEW_PRIVS = 6
    LANDLOCK = 7
    CLOSE_FDS = 8
    RLIMITS = 9
    SECCOMP = 10
    EXEC = 11
    TRACE = 12


class _Rlimit(ctypes.Structure):
    _fields_ = [("cur", ctypes.c_ulong), ("max", ctypes.c_ulong)]


@dataclass(slots=True)
class ChildSetup:
    """Everything the child needs, built before the fork."""

    executable: bytes
    argv: ctypes.Array[ctypes.c_char_p]
    envp: ctypes.Array[ctypes.c_char_p]
    argv_address: int
    envp_address: int
    cwd: str
    landlock: LandlockPlan | None
    programs: list[sc.PreparedProgram]
    rlimits: list[tuple[int, _Rlimit, int]]  # (resource, struct, address)
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    report_fd: int
    supervisor_pid: int
    trace_ack_fd: int | None = None  # set when a tracer will attach (ADR 0007)
    trace_go_fd: int | None = None
    _keep: list[object] = field(default_factory=list)


def _char_array(items: list[bytes]) -> ctypes.Array[ctypes.c_char_p]:
    array = (ctypes.c_char_p * (len(items) + 1))()
    for index, item in enumerate(items):
        array[index] = item
    array[len(items)] = None
    return array


def prepare_child(
    *,
    executable: str,
    argv: list[str],
    env: dict[str, str],
    cwd: str,
    landlock: LandlockPlan | None,
    programs: list[bytes],
    rlimits: list[tuple[int, int]],
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    report_fd: int,
    trace_fds: tuple[int, int] | None = None,
) -> ChildSetup:
    argv_bytes = [os.fsencode(a) for a in argv]
    env_bytes = [os.fsencode(k) + b"=" + os.fsencode(v) for k, v in env.items()]
    limits: list[tuple[int, _Rlimit, int]] = []
    for which, value in rlimits:
        struct_ = _Rlimit(value, value)
        limits.append((which, struct_, ctypes.addressof(struct_)))
    # Resolve the libc functions now, so the child does not have to.
    lib = libc()
    lib.setrlimit.argtypes = [ctypes.c_int, ctypes.c_void_p]
    lib.setrlimit.restype = ctypes.c_int
    lib.execve.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.execve.restype = ctypes.c_int
    argv_array, envp_array = _char_array(argv_bytes), _char_array(env_bytes)
    return ChildSetup(
        executable=os.fsencode(executable),
        argv=argv_array,
        envp=envp_array,
        argv_address=ctypes.addressof(argv_array),
        envp_address=ctypes.addressof(envp_array),
        cwd=cwd,
        landlock=landlock,
        programs=[sc.prepare_program(p) for p in programs],
        rlimits=limits,
        stdin_fd=stdin_fd,
        stdout_fd=stdout_fd,
        stderr_fd=stderr_fd,
        report_fd=report_fd,
        supervisor_pid=os.getpid(),
        trace_ack_fd=trace_fds[0] if trace_fds else None,
        trace_go_fd=trace_fds[1] if trace_fds else None,
        _keep=[argv_bytes, env_bytes],
    )


def set_nproc(setup: ChildSetup, which: int, value: int) -> None:
    """Add RLIMIT_NPROC, whose value is only known just before the fork."""
    struct_ = _Rlimit(value, value)
    setup.rlimits.append((which, struct_, ctypes.addressof(struct_)))


def restore_signals() -> None:
    for sig in signal.valid_signals():
        if sig in (signal.SIGKILL, signal.SIGSTOP):
            continue
        # Signals reserved by the C library refuse a new handler; they are not ours anyway.
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            signal.signal(sig, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, set())


def _restrict(plan: LandlockPlan) -> None:
    for bucket, path, optional in plan.proc_self:
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except FileNotFoundError:
            if optional:
                continue
            raise
        try:
            is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
            rights = rights_for(bucket, is_directory=is_dir, abi=plan.abi) & plan.handled_fs
            if rights:
                plan.ruleset.allow_path_fd(fd, rights)
        finally:
            os.close(fd)
    plan.ruleset.restrict_self()


def cloexec_all() -> None:
    try:
        syscall(
            SYS_CLOSE_RANGE,
            ctypes.c_uint(3),
            ctypes.c_uint(0xFFFFFFFF),
            ctypes.c_uint(CLOSE_RANGE_CLOEXEC),
        )
        return
    except OSError:
        pass  # close_range, or its CLOEXEC flag, is missing: do it one descriptor at a time
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            with contextlib.suppress(OSError):
                os.set_inheritable(fd, False)


def run_child(setup: ChildSetup) -> NoReturn:
    """Never returns: either ``execve`` succeeds or the child exits with a report."""
    report = bytearray(REPORT.size)
    step = Step.SESSION
    try:
        gc.disable()
        os.setsid()
        step = Step.SIGNALS
        restore_signals()
        step = Step.STDIO
        for source, target in ((setup.stdin_fd, 0), (setup.stdout_fd, 1), (setup.stderr_fd, 2)):
            if source != target:
                os.dup2(source, target)
            os.set_inheritable(target, True)
        step = Step.CHDIR
        os.chdir(setup.cwd)
        step = Step.PDEATHSIG
        prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        if os.getppid() != setup.supervisor_pid:
            raise ProcessLookupError("the supervisor exited before the tool started")
        step = Step.TRACE
        if setup.trace_ack_fd is not None and setup.trace_go_fd is not None:
            # Let the supervisor's tracer attach, wait until it has, then withdraw the
            # permission: children the tool forks are traced without it.
            with contextlib.suppress(OSError):
                prctl(PR_SET_PTRACER, setup.supervisor_pid)
            os.write(setup.trace_ack_fd, b"R")
            os.read(setup.trace_go_fd, 1)  # end of file also continues: tracing is optional
            with contextlib.suppress(OSError):
                prctl(PR_SET_PTRACER, 0)
        step = Step.NO_NEW_PRIVS
        set_no_new_privs()
        step = Step.LANDLOCK
        if setup.landlock is not None:
            _restrict(setup.landlock)
        step = Step.CLOSE_FDS
        cloexec_all()

        # Nothing below may allocate.
        lib = libc()
        setrlimit, prctl_raw, execve = lib.setrlimit, lib.prctl, lib.execve
        step = Step.RLIMITS
        for which, _struct, address in setup.rlimits:
            if setrlimit(which, address) != 0:
                raise OSError(ctypes.get_errno(), "setrlimit")
        step = Step.SECCOMP
        for program in setup.programs:
            if prctl_raw(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, program.address, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "prctl(PR_SET_SECCOMP)")
        step = Step.EXEC
        execve(setup.executable, setup.argv_address, setup.envp_address)
        REPORT.pack_into(report, 0, step, ctypes.get_errno())
        os.write(setup.report_fd, report)
    except BaseException as exc:
        try:
            err = getattr(exc, "errno", None) or 0
            REPORT.pack_into(report, 0, step, err)
            message = f"{type(exc).__name__}: {exc}".encode(errors="replace")[:2000]
            os.write(setup.report_fd, bytes(report) + message)
        except BaseException:  # noqa: S110 - nothing left to do but exit
            pass
    os._exit(EXIT_SETUP_FAILED)
