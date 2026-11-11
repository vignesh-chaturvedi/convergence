"""Expanding ``${VARIABLES}`` in policy paths and looking the paths up on this host.

Landlock attaches a rule to the inode a path refers to when the sandbox starts, following
symlinks. So the path must exist then, and what matters is where it really points. Both are
checked here, the same way the runtime will open them.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from convergence.policy.model import PathRule, Policy
from convergence.policy.rights import BUCKETS, Bucket

# /proc/self and /proc/thread-self name a different process for everyone who opens them, so
# they are resolved inside the sandboxed process at launch, never here.
PROC_SELF_PREFIXES = ("/proc/self", "/proc/thread-self")


class PathKind(StrEnum):
    DIRECTORY = "directory"
    FILE = "file"
    CHAR_DEVICE = "char-device"
    BLOCK_DEVICE = "block-device"
    SOCKET = "socket"
    FIFO = "fifo"
    MISSING = "missing"
    INACCESSIBLE = "inaccessible"
    SCRATCH = "scratch"  # the per-run scratch directory, created when the sandbox starts
    PROC_SELF = "proc-self"  # resolved inside the sandboxed process


@dataclass(frozen=True, slots=True)
class Variables:
    home: str | None
    cwd: str | None

    @classmethod
    def from_environment(cls, cwd: str | None = None) -> Variables:
        home = os.environ.get("HOME") or None
        try:
            current = cwd or os.getcwd()
        except OSError:
            current = None
        return cls(home=home, cwd=current)


@dataclass(frozen=True, slots=True)
class ResolvedPath:
    bucket: Bucket
    index: int
    rule: PathRule
    expanded: str | None  # after ${VARIABLE} substitution; None if it cannot be expanded here
    real: str | None  # symlinks resolved; None when missing, inaccessible, or special
    kind: PathKind
    error: str | None = None

    @property
    def location(self) -> str:
        return f"filesystem.{self.bucket}.{self.index}"

    @property
    def is_directory(self) -> bool:
        return self.kind in (PathKind.DIRECTORY, PathKind.SCRATCH)

    @property
    def is_device(self) -> bool:
        return self.kind in (PathKind.CHAR_DEVICE, PathKind.BLOCK_DEVICE)

    @property
    def may_contain_devices(self) -> bool:
        target = self.real or ""
        return self.is_device or (
            self.kind is PathKind.DIRECTORY and (target == "/dev" or target.startswith("/dev/"))
        )


def expand(path: str, variables: Variables) -> tuple[str | None, str | None]:
    """Return ``(expanded path, problem)``. ``${SCRATCH}`` cannot be expanded before a run."""
    if not path.startswith("${"):
        return path, None
    name, _, rest = path[2:].partition("}")
    if name == "SCRATCH":
        return None, None
    value = {"HOME": variables.home, "CWD": variables.cwd}.get(name)
    if not value:
        return None, f"${{{name}}} is not known here"
    return value.rstrip("/") + rest if rest else value, None


def _kind(mode: int) -> PathKind:
    if stat.S_ISDIR(mode):
        return PathKind.DIRECTORY
    if stat.S_ISCHR(mode):
        return PathKind.CHAR_DEVICE
    if stat.S_ISBLK(mode):
        return PathKind.BLOCK_DEVICE
    if stat.S_ISSOCK(mode):
        return PathKind.SOCKET
    if stat.S_ISFIFO(mode):
        return PathKind.FIFO
    return PathKind.FILE


def resolve_one(bucket: Bucket, index: int, rule: PathRule, variables: Variables) -> ResolvedPath:
    if rule.path.startswith("${SCRATCH}"):
        if rule.path.rstrip("/") != "${SCRATCH}":
            return ResolvedPath(
                bucket,
                index,
                rule,
                None,
                None,
                PathKind.MISSING,
                "only ${SCRATCH} itself can be granted: paths beneath it do not exist when the "
                "sandbox starts",
            )
        return ResolvedPath(bucket, index, rule, None, None, PathKind.SCRATCH)

    expanded, problem = expand(rule.path, variables)
    if expanded is None:
        return ResolvedPath(bucket, index, rule, None, None, PathKind.MISSING, problem)
    if any(expanded == p or expanded.startswith(p + "/") for p in PROC_SELF_PREFIXES):
        return ResolvedPath(bucket, index, rule, expanded, None, PathKind.PROC_SELF)

    try:
        info = os.stat(expanded)  # follows symlinks, as the runtime's O_PATH open will
    except FileNotFoundError:
        return ResolvedPath(bucket, index, rule, expanded, None, PathKind.MISSING, "does not exist")
    except OSError as exc:
        return ResolvedPath(
            bucket, index, rule, expanded, None, PathKind.INACCESSIBLE, exc.strerror or str(exc)
        )
    return ResolvedPath(
        bucket, index, rule, expanded, str(Path(expanded).resolve()), _kind(info.st_mode)
    )


def resolve_all(policy: Policy, variables: Variables) -> list[ResolvedPath]:
    resolved: list[ResolvedPath] = []
    for bucket in BUCKETS:
        for index, rule in enumerate(policy.filesystem.rules(bucket)):
            resolved.append(resolve_one(bucket, index, rule, variables))
    return resolved
