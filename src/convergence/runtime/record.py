"""The run record (``convergence.run/1``): what ran, under what, and how it ended.

Saved as JSON under ``$XDG_STATE_HOME/convergence/runs/`` (``~/.local/state`` when unset),
one file per run, readable only by the user. ``convergence run --json`` prints it instead of
passing the tool's output through.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

SCHEMA = "convergence.run/1"

Status = Literal["exited", "signaled", "timed-out", "interrupted", "not-started"]


@dataclass(slots=True)
class StreamRecord:
    total_bytes: int = 0
    kept: str = ""  # the first bytes, decoded as UTF-8 with replacement characters
    truncated: bool = False  # more was written than was kept
    passed_through: bool = False  # forwarded live to Convergence's own stdout or stderr


@dataclass(slots=True)
class Outcome:
    status: Status
    convergence_exit_code: int
    exit_code: int | None = None  # the tool's, when it exited normally
    signal: str | None = None  # the signal that ended the tool's first process
    descendants_killed: int = 0  # processes still running when the run ended
    error: str | None = None  # why the tool was not started


@dataclass(slots=True)
class Usage:
    """Resource use of every process of the run (RUSAGE_CHILDREN of the supervisor)."""

    user_cpu_seconds: float
    system_cpu_seconds: float
    max_rss_kb: int


@dataclass(slots=True)
class PolicyRef:
    path: str
    sha256: str
    name: str | None


@dataclass(slots=True)
class KernelInfo:
    release: str
    machine: str
    landlock_abi: int | None


@dataclass(slots=True)
class RunRecord:
    id: str
    convergence_version: str
    started_at: str
    command: list[str]
    cwd: str
    policy: PolicyRef
    kernel: KernelInfo
    outcome: Outcome
    schema: str = SCHEMA
    ended_at: str = ""
    duration_seconds: float = 0.0
    executable: str | None = None
    enforcement: dict[str, object] = field(default_factory=dict)
    degraded: list[dict[str, str]] = field(default_factory=list)
    usage: Usage | None = None
    stdout: StreamRecord = field(default_factory=StreamRecord)
    stderr: StreamRecord = field(default_factory=StreamRecord)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def new_run_id() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def runs_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return Path(base) / "convergence" / "runs"


def save(record: RunRecord, directory: Path | None = None) -> Path:
    """Write the record atomically, readable only by this user. Returns its path."""
    target_dir = directory or runs_dir()
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = target_dir / f"{record.id}.json"
    fd, temp = tempfile.mkstemp(prefix=".run-", dir=target_dir)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(record.to_json() + "\n")
        os.replace(temp, target)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    return target
