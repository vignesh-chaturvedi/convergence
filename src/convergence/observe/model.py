"""The observation format, ``convergence.observation/1`` (ADR 0008).

An observation is a list of events, each with an id that generated rules cite. Identical
events are merged and counted. An observation from strace is ``complete`` unless the run
timed out or the event cap was reached. An imported report is always partial.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter

SCHEMA = "convergence.observation/1"

EventKind = Literal["file", "exec", "net"]
# file: read, write, create, delete, rename-from, rename-to, readdir, truncate
# exec: exec
# net:  connect, send, bind
Op = Literal[
    "read",
    "write",
    "create",
    "delete",
    "rename-from",
    "rename-to",
    "readdir",
    "truncate",
    "exec",
    "connect",
    "send",
    "bind",
]


@dataclass(slots=True)
class Event:
    id: str
    kind: EventKind
    op: Op
    result: str = "ok"  # "ok", or the errno name the call failed with
    path: str | None = None  # absolute; the real path the kernel resolved, when known
    requested: str | None = None  # the path as the tool wrote it, when it differs
    protocol: Literal["tcp", "udp", "unix"] | None = None
    port: int | None = None
    address: str | None = None
    syscall: str = ""
    pid: int = 0  # the first process seen doing this
    count: int = 1  # how many times it was seen
    decoy: bool = False  # imported: the target was a decoy planted by the observer
    blocked: bool = False  # imported: the attempt was blocked by the observer's sandbox


@dataclass(slots=True)
class Exit:
    status: Literal["exited", "signaled", "timed-out", "interrupted", "not-observed"]
    exit_code: int | None = None
    signal: str | None = None


@dataclass(slots=True)
class Observation:
    id: str
    created_at: str
    source: Literal["strace", "divergence"]
    command: list[str]
    cwd: str
    home: str | None
    complete: bool
    events: list[Event]
    schema: str = SCHEMA
    exit: Exit = field(default_factory=lambda: Exit(status="not-observed"))
    duration_seconds: float = 0.0
    cpu_seconds: float = 0.0
    max_rss_kb: int = 0
    processes: list[int] = field(default_factory=list)  # pids seen; the first is the tool
    environment_names: list[str] = field(default_factory=list)  # names only, never values
    syscalls: dict[str, int] = field(default_factory=dict)  # every syscall seen, with counts
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    provenance: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


_ADAPTER: TypeAdapter[Observation] = TypeAdapter(Observation)


def load(path: str | Path) -> Observation:
    observation = _ADAPTER.validate_json(Path(path).read_text())
    if observation.schema != SCHEMA:
        raise ValueError(f"{path}: not a {SCHEMA} file (schema {observation.schema!r})")
    return observation


def adapter() -> TypeAdapter[Observation]:
    return _ADAPTER
