"""Resource oracle: did the run exceed the limits its policy sets?

Every number is measured by the harness from /proc and the clock, never reported by the
payload. Under the unconfined launcher the harness's safety limits are looser than the
policy (see escape/launchers.py), so a real resource attack is observed exceeding the
policy; under Convergence the policy's own limits must hold.

Case authors: keep the policy's limits small (for example memory_mb: 64,
max_processes: 8) and set cpu_seconds below wall_clock_seconds, so an unconfined run
exceeds the policy well before the harness's safety limits stop it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup
from escape.procs import SamplerOptions

WALL_CLOCK_GRACE = 2.0  # seconds allowed past the policy deadline for the kill to land
MIB = 1024 * 1024

Measure = Literal["processes", "memory", "cpu", "file-size", "open-files", "wall-clock"]


class ResourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    measure: Measure


def _largest_file(*roots: Path) -> int:
    largest = 0
    for root in roots:
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(current, d))]
            for name in filenames:
                try:
                    info = os.lstat(os.path.join(current, name))
                except OSError:
                    continue
                largest = max(largest, info.st_size)
    return largest


class ResourceDos(Oracle):
    type_name = "resource-dos"
    config_model = ResourceConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        config: ResourceConfig = self.config  # type: ignore[assignment]
        return Setup(sampler=SamplerOptions(fds=config.measure == "open-files"))

    def _limit(self, evidence: Evidence, name: str) -> int:
        value = getattr(evidence.policy.resources, name)
        if value is None:
            raise ValueError(f"a resource-dos case measuring this must set resources.{name}")
        return int(value)

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: ResourceConfig = self.config  # type: ignore[assignment]
        measure = config.measure
        peaks = evidence.peaks

        if measure == "processes":
            limit = self._limit(evidence, "max_processes")
            seen = evidence.max_concurrent - evidence.overhead_processes
            return Observation(
                seen > limit, f"peak {seen} concurrent processes; policy allows {limit}"
            )
        if measure == "memory":
            limit = self._limit(evidence, "memory_mb")
            rss = max((p.rss_kb for p in peaks), default=0) // 1024
            return Observation(
                rss > limit,
                f"peak resident memory {rss} MiB in one process; policy allows {limit} MiB",
            )
        if measure == "cpu":
            limit = self._limit(evidence, "cpu_seconds")
            cpu = max((p.cpu_seconds for p in peaks), default=0.0)
            return Observation(
                cpu > limit, f"peak CPU time {cpu:.1f} s in one process; policy allows {limit} s"
            )
        if measure == "file-size":
            limit = self._limit(evidence, "max_file_size_mb")
            largest = _largest_file(dirs.out, dirs.work)
            return Observation(
                largest > limit * MIB,
                f"largest file written {largest / MIB:.1f} MiB; policy allows {limit} MiB",
            )
        if measure == "open-files":
            limit = self._limit(evidence, "max_open_files")
            fds = max((p.fds for p in peaks), default=0)
            return Observation(
                fds > limit, f"peak {fds} open descriptors in one process; policy allows {limit}"
            )
        # wall-clock
        limit = evidence.policy.resources.wall_clock_seconds
        elapsed = evidence.exit.elapsed
        over = elapsed > limit + WALL_CLOCK_GRACE
        return Observation(
            over, f"ran {elapsed:.1f} s; policy allows {limit} s (+{WALL_CLOCK_GRACE:.0f} s grace)"
        )
