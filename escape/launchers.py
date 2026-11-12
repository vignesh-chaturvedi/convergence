"""How a case's payload is started: unconfined (now) or under Convergence (Phase 4).

Both launchers take the same :class:`LaunchSpec` and return a :class:`Running` handle, so the
runner, the sampler, and the oracles treat them identically. The only difference is what
stands between the payload and the host.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

from convergence.policy.model import Policy
from escape.expand import expand_policy_variables
from escape.procs import count_own_tasks

LIMITS_SCRIPT = Path(__file__).with_name("_limits.py")

OUTPUT_CAP = 1024 * 1024  # bytes kept per stream; the rest is counted, not stored
SAFETY_FACTOR = 4  # unconfined safety limits are this many times the policy's limits
MIB = 1024 * 1024


@dataclass(slots=True)
class LaunchSpec:
    argv: list[str]
    cwd: Path
    policy: Policy
    policy_path: Path
    supervisor_env: dict[str, str]  # the environment of the process that launches the tool
    scratch: Path  # stands in for ${SCRATCH} when no runtime resolves it
    home: str
    stdin: str | None = None
    inherit_fds: tuple[int, ...] = ()


@dataclass(slots=True)
class Exit:
    exit_code: int | None
    signal: str | None
    elapsed: float
    timed_out: bool


@dataclass(slots=True)
class Output:
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_total: int = 0
    stderr_total: int = 0

    @property
    def stdout_truncated(self) -> bool:
        return self.stdout_total > len(self.stdout)

    @property
    def stderr_truncated(self) -> bool:
        return self.stderr_total > len(self.stderr)


class _Reader(threading.Thread):
    """Drains a pipe, keeping at most OUTPUT_CAP bytes so a flood cannot exhaust the runner."""

    def __init__(self, stream: IO[bytes]) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.fd = stream.fileno()
        self.kept = bytearray()
        self.total = 0

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            while chunk := os.read(self.fd, 65536):
                self.total += len(chunk)
                room = OUTPUT_CAP - len(self.kept)
                if room > 0:
                    self.kept += chunk[:room]


@dataclass(slots=True)
class Running:
    process: subprocess.Popen[bytes]
    deadline: float  # seconds after start when the harness kills the process group
    started: float = field(default_factory=time.monotonic)
    _stdout: _Reader | None = None
    _stderr: _Reader | None = None

    @property
    def pid(self) -> int:
        return self.process.pid

    def wait(self) -> Exit:
        """Wait for the root process, killing its process group at the safety deadline."""
        timed_out = False
        try:
            self.process.wait(timeout=self.deadline)
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        elapsed = time.monotonic() - self.started
        code = self.process.returncode
        if code is not None and code < 0:
            return Exit(None, signal.Signals(-code).name, elapsed, timed_out)
        return Exit(code, None, elapsed, timed_out)

    def output(self, timeout: float = 2.0) -> Output:
        """Collect output once every process holding the pipes has gone."""
        out = Output()
        for reader, name in ((self._stdout, "stdout"), (self._stderr, "stderr")):
            if reader is None:
                continue
            reader.join(timeout=timeout)
            setattr(out, name, bytes(reader.kept))
            setattr(out, f"{name}_total", reader.total)
        return out


def _start(argv: list[str], spec: LaunchSpec, env: dict[str, str], deadline: float) -> Running:
    process = subprocess.Popen(  # noqa: S603 - the argv is the case's payload, by design
        argv,
        cwd=spec.cwd,
        env=env,
        stdin=subprocess.PIPE if spec.stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=spec.inherit_fds,
    )
    running = Running(process=process, deadline=deadline)
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("payload pipes were not created")
    running._stdout = _Reader(process.stdout)
    running._stderr = _Reader(process.stderr)
    running._stdout.start()
    running._stderr.start()
    if spec.stdin is not None and process.stdin is not None:
        with contextlib.suppress(BrokenPipeError, OSError):
            process.stdin.write(spec.stdin.encode())
        with contextlib.suppress(OSError):
            process.stdin.close()
    return running


class Launcher(Protocol):
    name: str
    overhead_processes: int  # processes the launcher itself adds to the run (e.g. a supervisor)

    def unavailable_reason(self) -> str | None: ...

    def start(self, spec: LaunchSpec) -> Running: ...


def _mem_total_mib() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 2048


def safety_limits(policy: Policy) -> dict[str, int]:
    """Rlimits for an unconfined run: looser than the policy, tight enough to protect the host.

    Exceeding the policy (but not these) is how a validity run proves a resource case is real.
    """
    res = policy.resources
    half_ram = max(_mem_total_mib() // 2, 256) * MIB
    limits: dict[str, int] = {}
    processes = res.max_processes * SAFETY_FACTOR if res.max_processes else 512
    limits["RLIMIT_NPROC"] = count_own_tasks() + processes
    limits["RLIMIT_DATA"] = min(
        res.memory_mb * SAFETY_FACTOR * MIB if res.memory_mb else half_ram, half_ram
    )
    if res.address_space_mb:
        limits["RLIMIT_AS"] = res.address_space_mb * SAFETY_FACTOR * MIB
    if res.cpu_seconds:
        limits["RLIMIT_CPU"] = res.cpu_seconds * SAFETY_FACTOR
    if res.max_file_size_mb:
        limits["RLIMIT_FSIZE"] = res.max_file_size_mb * SAFETY_FACTOR * MIB
    if res.max_open_files:
        limits["RLIMIT_NOFILE"] = res.max_open_files * SAFETY_FACTOR
    return limits


class UnconfinedLauncher:
    """No sandbox at all: the validity baseline.

    The payload inherits the launching process's whole environment (plus the policy's ``set``
    values) and the descriptors the oracle chose to leak, because a run with nothing
    protecting it would. Only harness safety limits apply, looser than the policy.
    """

    name = "unconfined"
    overhead_processes = 0

    def unavailable_reason(self) -> str | None:
        return None

    def start(self, spec: LaunchSpec) -> Running:
        env = dict(spec.supervisor_env)
        for name, value in spec.policy.environment.set.items():
            env[name] = expand_policy_variables(value, spec.home, str(spec.cwd), str(spec.scratch))
        argv = [
            expand_policy_variables(a, spec.home, str(spec.cwd), str(spec.scratch))
            for a in spec.argv
        ]
        limits = safety_limits(spec.policy)
        wrapped = [sys.executable, "-I", str(LIMITS_SCRIPT), json.dumps(limits), "--", *argv]
        wall = spec.policy.resources.wall_clock_seconds
        return _start(wrapped, spec, env, deadline=2 * wall + 5)


class ConvergenceLauncher:
    """The payload under ``convergence run`` with the case's policy (Phase 4).

    Invocation contract for Phase 4::

        convergence run --policy <policy_path> -- <argv...>

    started with cwd = ${WORKDIR}, the supervisor environment, and the oracle's descriptors
    passed through, so that ``convergence run`` itself is what must empty the environment
    and close the descriptors.
    """

    name = "convergence"
    overhead_processes = 1  # the convergence supervisor

    def __init__(self) -> None:
        self._reason: str | None = None
        self._checked = False

    def unavailable_reason(self) -> str | None:
        if not self._checked:
            self._checked = True
            probe = subprocess.run(
                [sys.executable, "-m", "convergence", "run", "--help"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            if probe.returncode != 0:
                self._reason = (
                    "`convergence run` is not implemented yet (Phase 4 in PLAN.md); "
                    "nothing was executed"
                )
        return self._reason

    def start(self, spec: LaunchSpec) -> Running:
        reason = self.unavailable_reason()
        if reason is not None:
            raise RuntimeError(reason)
        argv = [
            sys.executable,
            "-m",
            "convergence",
            "run",
            "--policy",
            str(spec.policy_path),
            "--",
            *spec.argv,
        ]
        wall = spec.policy.resources.wall_clock_seconds
        return _start(argv, spec, dict(spec.supervisor_env), deadline=wall + 15)


LAUNCHERS: dict[str, type[UnconfinedLauncher] | type[ConvergenceLauncher]] = {
    "unconfined": UnconfinedLauncher,
    "convergence": ConvergenceLauncher,
}


def _expanded_argv(spec: LaunchSpec) -> list[str]:
    """The payload with ${HOME}, ${CWD}, ${SCRATCH} resolved to the run's stable paths."""
    return [
        expand_policy_variables(a, spec.home, str(spec.cwd), str(spec.scratch)) for a in spec.argv
    ]


class ObserveLauncher:
    """``convergence observe`` for the false-denial harness: unconfined, under strace.

    The argv is expanded to the case's own paths, so that the policy generated from the
    observation names the same paths the confined runs will use.
    """

    name = "observe"
    overhead_processes = 2  # observe's supervisor and strace

    def __init__(self, out: Path) -> None:
        self.out = out

    def unavailable_reason(self) -> str | None:
        from convergence.runtime.tracer import find_strace

        return None if find_strace() else "strace is not installed"

    def start(self, spec: LaunchSpec) -> Running:
        wall = spec.policy.resources.wall_clock_seconds
        argv = [sys.executable, "-m", "convergence", "observe", "--out", str(self.out)]
        argv += ["--timeout", str(wall), "--", *_expanded_argv(spec)]
        return _start(argv, spec, dict(spec.supervisor_env), deadline=wall + 15)


class PolicyLauncher:
    """``convergence run`` with a given policy instead of the case's own (a generated one)."""

    name = "generated-policy"
    overhead_processes = 1  # the convergence supervisor

    def __init__(self, policy: Path) -> None:
        self.policy = policy

    def unavailable_reason(self) -> str | None:
        return None if self.policy.is_file() else f"no policy at {self.policy}"

    def start(self, spec: LaunchSpec) -> Running:
        wall = spec.policy.resources.wall_clock_seconds
        argv = [sys.executable, "-m", "convergence", "run", "--no-record"]
        argv += ["--policy", str(self.policy), "--", *_expanded_argv(spec)]
        return _start(argv, spec, dict(spec.supervisor_env), deadline=wall + 15)
