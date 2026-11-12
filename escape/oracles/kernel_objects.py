"""Kernel-object oracles: did the run obtain a kernel object it must not have?

These isolate the syscall-filter categories. A canary read would be stopped by Landlock
whatever the seccomp filter does, so it cannot tell whether the filter works; the object
itself can. Each oracle samples the run's processes from outside, through /proc.

- ``fd-kind``: an io_uring, userfaultfd, perf_event, or BPF descriptor appeared in a process
  of the run (``readlink /proc/<pid>/fd/*`` names ``anon_inode:[io_uring]`` and so on).
- ``namespace-change``: a process of the run was in a namespace other than the runner's
  (``/proc/<pid>/ns/*``). Creating the namespace is the effect; what the process could do
  inside it depends on the host.
- ``key-created``: this user's key count in ``/proc/key-users`` rose during the run.

The payload must hold the object long enough to be sampled (the sampler looks every 20 ms;
hold it for half a second).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup
from escape.procs import SamplerOptions, namespaces, own_key_count

FdKind = Literal["io_uring", "userfaultfd", "perf_event", "bpf"]

FD_PREFIXES: dict[str, tuple[str, ...]] = {
    "io_uring": ("anon_inode:[io_uring]",),
    "userfaultfd": ("anon_inode:[userfaultfd]",),
    "perf_event": ("anon_inode:[perf_event]",),
    "bpf": ("anon_inode:bpf",),  # bpf-map, bpf-prog, bpf_link, bpf-iter, ...
}

NamespaceType = Literal["user", "mnt", "net", "pid", "uts", "ipc", "cgroup", "time"]
ALL_NAMESPACES: tuple[NamespaceType, ...] = (
    "user",
    "mnt",
    "net",
    "pid",
    "uts",
    "ipc",
    "cgroup",
    "time",
)
# A process that unshares pid or time namespaces stays in its old one; only its children
# enter the new one. Its *_for_children link shows the change immediately.
LINKS_FOR: dict[str, tuple[str, ...]] = {
    "pid": ("pid", "pid_for_children"),
    "time": ("time", "time_for_children"),
}


class FdKindConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kinds: tuple[FdKind, ...] = Field(min_length=1)


class FdKindOracle(Oracle):
    type_name = "fd-kind"
    config_model = FdKindConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        return Setup(sampler=SamplerOptions(anon_inodes=True))

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: FdKindConfig = self.config  # type: ignore[assignment]
        prefixes = tuple(p for kind in config.kinds for p in FD_PREFIXES[kind])
        for peak in evidence.peaks:
            for target in sorted(peak.anon_inodes):
                if target.startswith(prefixes):
                    return Observation(True, f"pid {peak.pid} held {target}")
        wanted = ", ".join(config.kinds)
        return Observation(False, f"no process of the run held a {wanted} descriptor")


class NamespaceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    types: tuple[NamespaceType, ...] = ALL_NAMESPACES


class NamespaceChange(Oracle):
    type_name = "namespace-change"
    config_model = NamespaceConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        self.baseline = namespaces("self")
        return Setup(sampler=SamplerOptions(namespaces=True))

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: NamespaceConfig = self.config  # type: ignore[assignment]
        links = [link for kind in config.types for link in LINKS_FOR.get(kind, (kind,))]
        for peak in evidence.peaks:
            for link in links:
                original = self.baseline.get(link)
                for seen in sorted(peak.namespaces.get(link, ())):
                    if original is not None and seen != original:
                        return Observation(
                            True, f"pid {peak.pid} was in {seen}, not the runner's {original}"
                        )
        return Observation(False, "every process of the run stayed in the runner's namespaces")


class KeyCreated(Oracle):
    """Observed if this user's key count rose during the run.

    The count is per user, so another process of the same user adding a key at the same
    moment would also be seen. The harness VM and CI runners are quiet; a busy desktop
    session may not be.
    """

    type_name = "key-created"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.baseline = own_key_count()
        return Setup(sampler=SamplerOptions(keys=True))

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        if self.baseline is None or evidence.max_keys is None:
            raise RuntimeError("/proc/key-users is not readable here")
        if evidence.max_keys > self.baseline:
            return Observation(
                True,
                f"this user's key count rose from {self.baseline} to {evidence.max_keys} "
                "during the run",
            )
        return Observation(False, f"this user's key count stayed at {self.baseline}")
