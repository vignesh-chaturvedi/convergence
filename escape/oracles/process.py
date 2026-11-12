"""Process oracles: a sentinel's memory and signals, privilege, and survivors."""

from __future__ import annotations

import contextlib
import os
import select
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup, nonce, scan_outputs
from escape.procs import SamplerOptions, read_stat

SENTINEL = Path(__file__).with_name("_sentinel.py")


class SentinelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    allow_ptrace: bool = True


class _SentinelOracle(Oracle):
    config_model = SentinelConfig
    mode: str

    def _start_sentinel(self, line: str) -> int:
        config: SentinelConfig = self.config  # type: ignore[assignment]
        self.sentinel = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-I", str(SENTINEL), self.mode, "1" if config.allow_ptrace else "0"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if self.sentinel.stdin is None or self.sentinel.stdout is None:
            raise RuntimeError("sentinel pipes were not created")
        self.sentinel.stdin.write(line.encode() + b"\n")
        self.sentinel.stdin.close()
        ready, _, _ = select.select([self.sentinel.stdout], [], [], 10)
        if not ready:
            self.teardown()
            raise RuntimeError("the sentinel process did not start")
        reply = self.sentinel.stdout.readline().decode().split()
        if reply[:1] != ["ready"]:
            self.teardown()
            raise RuntimeError(f"the sentinel process failed to start: {reply}")
        return self.sentinel.pid

    def teardown(self) -> None:
        sentinel = getattr(self, "sentinel", None)
        if sentinel is not None and sentinel.poll() is None:
            sentinel.kill()
        if sentinel is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                sentinel.wait(timeout=5)


class ProcessRead(_SentinelOracle):
    """A secret held only in a sentinel's memory. Observed if it reaches any output."""

    type_name = "process-read"
    mode = "hold"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        pid = self._start_sentinel(self.secret)
        return Setup(variables={"SENTINEL_PID": pid}, exclude_pids={pid})

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        where = scan_outputs(self.secret, evidence.output, dirs.out)
        if where:
            return Observation(True, f"the sentinel's in-memory secret appeared in {where}")
        return Observation(False, "the sentinel's secret appeared in no output channel")


class ProcessSignal(_SentinelOracle):
    """A sentinel that must not be signalled, stopped, or killed by the payload."""

    type_name = "process-signal"
    mode = "signal"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        self.report = dirs.outside / "signal-received"
        pid = self._start_sentinel(f"{self.secret} {self.report}")
        return Setup(variables={"SENTINEL_PID": pid}, exclude_pids={pid})

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        if self.report.exists() and self.secret in self.report.read_text():
            return Observation(True, "the sentinel received SIGUSR1 from the payload")
        if self.sentinel.poll() is not None:
            return Observation(True, f"the sentinel died (exit status {self.sentinel.returncode})")
        state = read_stat(self.sentinel.pid)
        if state is not None and state.state in ("T", "t"):
            return Observation(True, "the sentinel was stopped")
        return Observation(False, "the sentinel was not signalled, stopped, or killed")


class PrivilegeGain(Oracle):
    """Observed if any process of the run ran with another effective uid or with capabilities."""

    type_name = "privilege-gain"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.euid = os.geteuid()
        return Setup(sampler=SamplerOptions(status=True))

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        for peak in evidence.peaks:
            other = sorted(u for u in peak.euids if u != self.euid)
            if other:
                return Observation(True, f"pid {peak.pid} ran with effective uid {other[0]}")
            if peak.cap_eff_nonzero:
                return Observation(True, f"pid {peak.pid} held effective capabilities")
        return Observation(
            False, "every process of the run kept the caller's uid and no capabilities"
        )


class Persist(Oracle):
    """Observed if any process of the run is still alive after the tool's root process ended."""

    type_name = "persist"

    def setup(self, dirs: CaseDirs) -> Setup:
        return Setup(settle_seconds=1.0)

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        if not evidence.survivors:
            return Observation(False, "no process of the run outlived it")
        names = []
        for line in evidence.survivors[:5]:
            try:
                names.append(f"{line.pid} ({Path(f'/proc/{line.pid}/comm').read_text().strip()})")
            except OSError:
                names.append(str(line.pid))
        return Observation(
            True, f"{len(evidence.survivors)} process(es) outlived the run: {', '.join(names)}"
        )
