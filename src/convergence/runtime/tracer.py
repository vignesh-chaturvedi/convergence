"""The optional strace tracer for denial capture (ADR 0007). Never part of enforcement.

The tool names the supervisor as its tracer (``PR_SET_PTRACER``) and waits. The supervisor
starts strace, which attaches with ``-p``, and releases the tool once the kernel shows it
traced. strace runs in its own session with ``no_new_privs`` and a seccomp filter that
denies sockets and the built-in deny list except the calls tracing needs. Its output goes
to a private directory removed after the run. If anything here fails, the run goes on
untraced.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from convergence.kernel import seccomp as sc
from convergence.kernel._libc import set_no_new_privs
from convergence.runtime import child as child_mod
from convergence.runtime.filters import build_tracer_program

STRACE_CANDIDATES = ("/usr/bin/strace", "/bin/strace", "/usr/local/bin/strace")
ATTACH_SECONDS = 5.0
FINISH_SECONDS = 5.0


def find_strace() -> str | None:
    return next((p for p in STRACE_CANDIDATES if os.access(p, os.X_OK)), None)


@dataclass(slots=True)
class Tracer:
    strace: str
    directory: Path
    program: sc.PreparedProgram | None
    pid: int | None = None
    detail: str = ""
    _reaped: bool = field(default=False)

    @classmethod
    def prepare(cls) -> tuple[Tracer | None, str]:
        strace = find_strace()
        if strace is None:
            return None, "strace is not installed"
        program: sc.PreparedProgram | None = None
        try:
            program = sc.prepare_program(build_tracer_program(sc.library()))
        except (sc.SeccompUnavailable, OSError, ValueError) as exc:
            return None, f"could not build the tracer's seccomp filter: {exc}"
        directory = Path(tempfile.mkdtemp(prefix="convergence-trace-"))
        return cls(strace=strace, directory=directory, program=program), ""

    def argv(self, target: int) -> list[str]:
        return [
            self.strace,
            "-f",
            "-ff",
            "-q",
            "-y",
            "-s",
            "256",
            "-e",
            "status=failed",
            "-o",
            str(self.directory / "trace"),
            "-p",
            str(target),
        ]

    def start(self, target: int) -> None:
        """Fork and exec strace. Must be called while the supervisor is single-threaded."""
        argv = self.argv(target)
        log = self.directory / "strace.log"
        # See supervise(): no handler may run between the fork and the child's own setup.
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, signal.valid_signals())
        try:
            pid = os.fork()
        except BaseException:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            raise
        if pid == 0:
            try:
                os.setsid()
                child_mod.restore_signals()
                null = os.open(os.devnull, os.O_RDONLY)
                out = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(null, 0)
                os.dup2(out, 1)
                os.dup2(out, 2)
                child_mod.cloexec_all()
                set_no_new_privs()
                if self.program is not None:
                    sc.install_program(self.program)
                os.execve(  # noqa: S606 - a fixed strace argv, no shell
                    self.strace, argv, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                )
            except BaseException:  # noqa: S110 - the supervisor notices strace never attached
                pass
            os._exit(127)
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        self.pid = pid

    def _log(self) -> str:
        try:
            text = (self.directory / "strace.log").read_text(errors="replace").strip()
        except OSError:
            return ""
        return text.splitlines()[-1][:300] if text else ""

    def wait_attached(self, target: int) -> bool:
        """Wait until the kernel shows ``target`` traced by strace."""
        if self.pid is None:
            return False
        end = time.monotonic() + ATTACH_SECONDS
        status = Path(f"/proc/{target}/status")
        while time.monotonic() < end:
            try:
                for line in status.read_text().splitlines():
                    if line.startswith("TracerPid:") and int(line.split()[1]) == self.pid:
                        return True
            except OSError:
                break
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self._reaped = True
                self.detail = f"strace exited before attaching: {self._log() or 'no output'}"
                return False
            time.sleep(0.01)
        if not self.detail:
            self.detail = f"strace did not attach within {ATTACH_SECONDS:.0f} s: {self._log()}"
        return False

    def finish(self) -> None:
        """Let strace flush and exit once its tracees are gone; kill it if it lingers."""
        if self.pid is None or self._reaped:
            return
        end = time.monotonic() + FINISH_SECONDS
        while time.monotonic() < end:
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self._reaped = True
                return
            time.sleep(0.01)
        with contextlib.suppress(ProcessLookupError):
            os.kill(self.pid, signal.SIGKILL)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(self.pid, 0)
        self._reaped = True

    def stop(self) -> None:
        if self.pid is not None and not self._reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(self.pid, 0)
            self._reaped = True

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.directory, ignore_errors=True)
