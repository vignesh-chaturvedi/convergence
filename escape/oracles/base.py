"""The oracle interface.

An oracle answers one question with ground truth the harness controls: **did the effect
happen?** For an attack, "yes" means it escaped. For a control, "yes" means the workload did
its job. The payload's own output is only ever searched for a secret it should not have been
able to obtain; it is never read as a claim.
"""

from __future__ import annotations

import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from convergence.policy.model import Policy
from escape.expand import VarValue
from escape.launchers import Exit, Output
from escape.procs import Peak, SamplerOptions, StatLine

MAX_SCAN_BYTES = 16 * 1024 * 1024


class NoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


@dataclass(slots=True)
class CaseDirs:
    """Fresh directories for one case. ``outside`` is never granted by any policy."""

    root: Path
    work: Path
    out: Path
    outside: Path

    @classmethod
    def create(cls, root: Path) -> CaseDirs:
        dirs = cls(root, root / "work", root / "out", root / "outside")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in (dirs.work, dirs.out, dirs.outside):
            path.mkdir(mode=0o700)
        return dirs


@dataclass(slots=True)
class Setup:
    """What an oracle contributes to a run."""

    variables: dict[str, VarValue] = field(default_factory=dict)
    supervisor_env: dict[str, str] = field(default_factory=dict)
    inherit_fds: tuple[int, ...] = ()
    exclude_pids: set[int] = field(default_factory=set)
    sampler: SamplerOptions = field(default_factory=SamplerOptions)
    settle_seconds: float = 0.05  # wait after the root exits before looking for survivors


@dataclass(slots=True)
class Evidence:
    """Everything an oracle may consult after the run."""

    exit: Exit
    output: Output
    peaks: list[Peak]
    max_concurrent: int
    survivors: list[StatLine]
    overhead_processes: int
    policy: Policy


@dataclass(frozen=True, slots=True)
class Observation:
    observed: bool
    evidence: str


class Oracle(ABC):
    type_name: ClassVar[str]
    config_model: ClassVar[type[BaseModel]] = NoConfig

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = self.config_model.model_validate(config)

    @abstractmethod
    def setup(self, dirs: CaseDirs) -> Setup: ...

    @abstractmethod
    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation: ...

    def teardown(self) -> None:  # noqa: B027 - optional hook
        """Release anything ``setup`` created outside ``dirs`` (processes, sockets)."""


def nonce() -> str:
    return "convergence-canary-" + secrets.token_hex(16)


def scan_outputs(
    needle: str, output: Output, out_dir: Path, *, files_only: bool = False
) -> str | None:
    """Where ``needle`` appears among the payload's output channels, or None.

    Channels are stdout, stderr, and regular files under ``out_dir``. Symlinks are never
    followed: a payload could otherwise point one at a host file and make the harness read
    it, which would look like an escape that never happened.
    """
    raw = needle.encode()
    if not files_only:
        if raw in output.stdout:
            return "stdout"
        if raw in output.stderr:
            return "stderr"
    for current, dirnames, filenames in os.walk(out_dir, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(current, d))]
        for name in filenames:
            path = Path(current, name)
            try:
                info = path.lstat()
            except OSError:
                continue
            if not path.is_file() or path.is_symlink() or info.st_size > MAX_SCAN_BYTES:
                continue
            try:
                if raw in path.read_bytes():
                    return f"out/{path.relative_to(out_dir)}"
            except OSError:
                continue
    return None
