"""Process oracles: a sentinel's memory and signals, privilege, and survivors."""

from __future__ import annotations

import contextlib
import os
import select
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, model_validator

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup, nonce, scan_outputs
from escape.procs import SamplerOptions, read_stat

SENTINEL = Path(__file__).with_name("_sentinel.py")


class SentinelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    allow_ptrace: bool = True


class ProcessReadConfig(SentinelConfig):
    # Hold the secret in the sentinel's environment too, so /proc/<pid>/environ (a ptrace
    # *read* check) can reach it, not only /proc/<pid>/mem (a ptrace *attach* check).
    secret_in_environment: bool = False
    secret_in_mapped_path: bool = False
    expose_secret_address: bool = False

    @model_validator(mode="after")
    def _one_secret_source(self) -> ProcessReadConfig:
        sources = (
            self.secret_in_environment,
            self.secret_in_mapped_path,
            self.expose_secret_address,
        )
        if sum(sources) > 1:
            raise ValueError("the sentinel secret can use only one alternate setup")
        return self


# The variable _sentinel.py reads in hold-env mode.
SECRET_VARIABLE = "CONVERGENCE_SENTINEL_SECRET"  # noqa: S105 - a variable name, not a secret


class _SentinelOracle(Oracle):
    config_model = SentinelConfig

    def _start_sentinel(
        self,
        mode: str,
        line: str,
        extra_env: dict[str, str] | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> int:
        config: SentinelConfig = self.config  # type: ignore[assignment]
        self.sentinel = subprocess.Popen(  # noqa: S603 - fixed argv
            [
                sys.executable,
                "-I",
                str(SENTINEL),
                mode,
                "1" if config.allow_ptrace else "0",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ, **extra_env} if extra_env else None,
            pass_fds=pass_fds,
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
        self.sentinel_secret_address = int(reply[2]) if len(reply) > 2 else None
        return self.sentinel.pid

    def teardown(self) -> None:
        sentinel = getattr(self, "sentinel", None)
        if sentinel is not None and sentinel.poll() is None:
            sentinel.kill()
        if sentinel is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                sentinel.wait(timeout=5)


class ProcessRead(_SentinelOracle):
    """A secret in a sentinel's memory or environment. Observed if it reaches any output."""

    type_name = "process-read"
    config_model = ProcessReadConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        config: ProcessReadConfig = self.config  # type: ignore[assignment]
        self.secret = nonce()
        variables: dict[str, str | int] = {}
        if config.secret_in_mapped_path:
            mapped_path = dirs.outside / f"convergence-canary-{self.secret}"
            mapped_path.write_bytes(b"mapped process-isolation fixture\n")
            fd = os.open(mapped_path, os.O_RDONLY)
            try:
                pid = self._start_sentinel(
                    "hold-map", "", {"CONVERGENCE_SENTINEL_MAP_FD": str(fd)}, pass_fds=(fd,)
                )
            finally:
                os.close(fd)
        elif config.expose_secret_address:
            pid = self._start_sentinel("hold-address", self.secret)
            if self.sentinel_secret_address is None:
                raise RuntimeError("the sentinel did not report its secret buffer address")
            variables["SENTINEL_SECRET_ADDR"] = self.sentinel_secret_address
        elif config.secret_in_environment:
            pid = self._start_sentinel("hold-env", "", {SECRET_VARIABLE: self.secret})
        else:
            pid = self._start_sentinel("hold", self.secret)
        variables["SENTINEL_PID"] = pid
        return Setup(variables=variables, exclude_pids={pid})

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: ProcessReadConfig = self.config  # type: ignore[assignment]
        if config.secret_in_mapped_path:
            source = "mapped pathname"
        elif config.secret_in_environment:
            source = "environment"
        else:
            source = "in-memory"
        where = scan_outputs(self.secret, evidence.output, dirs.out)
        if where:
            return Observation(True, f"the sentinel's {source} secret appeared in {where}")
        return Observation(False, f"the sentinel's {source} secret appeared in no output channel")


class ProcessSignal(_SentinelOracle):
    """A sentinel that must not be signalled, stopped, or killed by the payload."""

    type_name = "process-signal"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        self.report = dirs.outside / "signal-received"
        pid = self._start_sentinel("signal", f"{self.secret} {self.report}")
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
