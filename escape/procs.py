"""Observing a run's processes from outside, through ``/proc``.

This is how the harness measures what a payload did to the host: how many processes it
made, how much memory and CPU each used, how many descriptors each held, whether any ran
with raised privileges, whether a marker binary was mapped executable, and which processes
outlived the run. Nothing here trusts the payload: it reads kernel state.

A process belongs to a run if it is the run's root, is in the root's session, descends from
a member, or was reparented to the runner (the runner is a child subreaper, so a daemon that
double-forks out of the session still lands here).
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

PR_SET_CHILD_SUBREAPER = 36

Identity = tuple[int, int]  # (pid, starttime): survives pid reuse


@dataclass(frozen=True, slots=True)
class StatLine:
    pid: int
    state: str
    ppid: int
    pgrp: int
    session: int
    cpu_ticks: int
    rss_pages: int
    starttime: int

    @property
    def identity(self) -> Identity:
        return (self.pid, self.starttime)

    @property
    def alive(self) -> bool:
        return self.state not in ("Z", "X")


def read_stat(pid: int) -> StatLine | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    rest = text[text.rfind(")") + 2 :].split()
    try:
        return StatLine(
            pid=pid,
            state=rest[0],
            ppid=int(rest[1]),
            pgrp=int(rest[2]),
            session=int(rest[3]),
            cpu_ticks=int(rest[11]) + int(rest[12]),
            rss_pages=int(rest[21]),
            starttime=int(rest[19]),
        )
    except (IndexError, ValueError):
        return None


def own_processes() -> dict[int, StatLine]:
    """Every process owned by this user, keyed by pid."""
    uid = os.getuid()
    found: dict[int, StatLine] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
        except OSError:
            continue
        line = read_stat(int(entry.name))
        if line is not None:
            found[line.pid] = line
    return found


def count_own_processes() -> int:
    return sum(1 for line in own_processes().values() if line.alive)


def read_status(pid: int) -> tuple[int | None, int | None]:
    """(effective uid, effective capabilities) from /proc/<pid>/status."""
    euid = cap_eff = None
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                euid = int(line.split()[2])
            elif line.startswith("CapEff:"):
                cap_eff = int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return euid, cap_eff


def count_fds(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def maps_executable(pid: int, device: str, inode: int) -> bool:
    """Whether ``pid`` has the given file mapped with execute permission."""
    try:
        text = Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return False
    needle_inode = str(inode)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "x" in parts[1] and parts[3] == device and parts[4] == needle_inode:
            return True
    return False


def device_of(path: Path) -> tuple[str, int]:
    """The (``maj:min`` as /proc/<pid>/maps prints it, inode) of a file."""
    info = path.stat()
    return f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}", info.st_ino


def become_subreaper() -> None:
    """Make orphaned descendants reparent to this process instead of init."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"PR_SET_CHILD_SUBREAPER: {os.strerror(err)}")


def reap_zombie_children(known: set[int]) -> None:
    """Reap orphans that were reparented here and have since exited.

    ``known`` lists children this process waits for elsewhere (Popen objects); those are
    left alone.
    """
    me = os.getpid()
    for line in own_processes().values():
        if line.ppid == me and not line.alive and line.pid not in known:
            with contextlib.suppress(ChildProcessError, OSError):
                os.waitpid(line.pid, os.WNOHANG)


@dataclass(slots=True)
class Peak:
    """The highest values seen for one process over the run."""

    pid: int
    rss_kb: int = 0
    cpu_seconds: float = 0.0
    fds: int = 0
    euids: set[int] = field(default_factory=set)
    cap_eff_nonzero: bool = False
    marker_mapped: bool = False


@dataclass(slots=True)
class SamplerOptions:
    status: bool = False  # read euid and CapEff (privilege oracle)
    fds: bool = False  # count descriptors (fd-exhaustion oracle)
    marker: tuple[str, int] | None = None  # (device, inode) to look for in executable maps
    interval: float = 0.02


class Sampler:
    """Samples a run's processes on a background thread."""

    def __init__(self, root_pid: int, options: SamplerOptions, exclude: set[int]) -> None:
        self.root_pid = root_pid
        self.options = options
        self.exclude = set(exclude)
        self.runner_pid = os.getpid()
        self.page_kb = os.sysconf("SC_PAGE_SIZE") // 1024
        self.ticks = os.sysconf("SC_CLK_TCK")
        self.members: dict[Identity, Peak] = {}
        self.max_concurrent = 0
        self.samples = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._loop, name="escape-sampler", daemon=True)

    def start(self) -> None:
        self.sample_once()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(self.options.interval):
            self.sample_once()

    def _current_members(self, procs: dict[int, StatLine]) -> list[StatLine]:
        known = {identity for identity in self.members}
        children: dict[int, list[int]] = {}
        for line in procs.values():
            children.setdefault(line.ppid, []).append(line.pid)

        member_pids: set[int] = set()
        frontier: list[int] = []
        for line in procs.values():
            if line.pid in self.exclude or line.pid == self.runner_pid:
                continue
            if (
                line.pid == self.root_pid
                or line.session == self.root_pid
                or line.identity in known
                or (line.ppid == self.runner_pid and line.pid != self.root_pid)
            ):
                member_pids.add(line.pid)
                frontier.append(line.pid)
        # Descendants of any member are members too.
        while frontier:
            for child in children.get(frontier.pop(), []):
                if child not in member_pids and child not in self.exclude:
                    member_pids.add(child)
                    frontier.append(child)
        return [procs[pid] for pid in member_pids]

    def sample_once(self) -> None:
        procs = own_processes()
        members = self._current_members(procs)
        alive = [m for m in members if m.alive]
        with self._lock:
            self.samples += 1
            self.max_concurrent = max(self.max_concurrent, len(alive))
            for line in alive:
                peak = self.members.setdefault(line.identity, Peak(pid=line.pid))
                peak.rss_kb = max(peak.rss_kb, line.rss_pages * self.page_kb)
                peak.cpu_seconds = max(peak.cpu_seconds, line.cpu_ticks / self.ticks)
                if self.options.fds:
                    fds = count_fds(line.pid)
                    if fds is not None:
                        peak.fds = max(peak.fds, fds)
                if self.options.status:
                    euid, cap_eff = read_status(line.pid)
                    if euid is not None:
                        peak.euids.add(euid)
                    if cap_eff:
                        peak.cap_eff_nonzero = True
                if self.options.marker and not peak.marker_mapped:
                    device, inode = self.options.marker
                    peak.marker_mapped = maps_executable(line.pid, device, inode)

    def alive_members(self, *, excluding_root: bool) -> list[StatLine]:
        procs = own_processes()
        members = [m for m in self._current_members(procs) if m.alive]
        if excluding_root:
            members = [m for m in members if m.pid != self.root_pid]
        return members

    def peaks(self) -> list[Peak]:
        with self._lock:
            return list(self.members.values())


def kill_all(lines: list[StatLine]) -> None:
    """SIGKILL each process, if it is still the same process (pid and start time)."""
    for line in lines:
        current = read_stat(line.pid)
        if current is not None and current.starttime == line.starttime:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(line.pid, 9)
