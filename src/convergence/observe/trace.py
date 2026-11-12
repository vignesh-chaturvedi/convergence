"""Parsing ``strace -f -ff -yy`` output into observation events (ADR 0008).

Each process has its own file (``trace.<pid>``). Every line is a system call, a signal, or
an exit notice. With ``-yy``, descriptors carry the real path they refer to
(``3</tmp/obs/in.txt>``) and sockets their protocol (``3<TCP:[186039]>``). Relative paths in
``*at`` calls carry their base directory (``AT_FDCWD</tmp/obs>``).
"""

from __future__ import annotations

import codecs
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from convergence.observe.model import Event, Op

LINE = re.compile(
    r"^(?P<name>[a-z_][a-z_0-9]*)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?|0x[0-9a-f]+)(?P<rest>.*)$"
)
UNFINISHED = re.compile(r"^(?P<head>[a-z_][a-z_0-9]*\(.*?)\s*<unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (?P<name>[a-z_][a-z_0-9]*) resumed>(?P<tail>.*)$")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
BASE_DIR = re.compile(r"^(?:AT_FDCWD|\d+)<(?P<dir>[^>]*)>")
FD_PATH = re.compile(r"^\d+<(?P<path>[^>]*)>")
RETURN_PATH = re.compile(r"^<(?P<path>[^>]*)>")
ERRNO = re.compile(r"^\s*(?P<errno>E[A-Z0-9]+)\b")
SOCKET_KIND = re.compile(r"^\d+<(?P<kind>TCP|UDP|UNIX)[A-Za-z0-9-]*:")
PORT = re.compile(r"sin6?_port=htons\((?P<port>\d+)\)")
ADDR4 = re.compile(r'sin_addr=inet_addr\("(?P<addr>[^"]*)"\)')
ADDR6 = re.compile(r'inet_pton\(AF_INET6, "(?P<addr>[^"]*)"')
SUN_PATH = re.compile(r'sun_path=(?P<abstract>@?)"(?P<path>(?:[^"\\]|\\.)*)"')

OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
CREATE_CALLS = frozenset(
    {"mkdir", "mkdirat", "mknod", "mknodat", "symlink", "symlinkat", "link", "linkat"}
)
DELETE_CALLS = frozenset({"unlink", "unlinkat", "rmdir"})
RENAME_CALLS = frozenset({"rename", "renameat", "renameat2"})
EXEC_CALLS = frozenset({"execve", "execveat"})
READDIR_CALLS = frozenset({"getdents", "getdents64"})
NET_CALLS = {
    "connect": "connect",
    "sendto": "send",
    "sendmsg": "send",
    "sendmmsg": "send",
    "bind": "bind",
}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR")

DEFAULT_EVENT_CAP = 100_000


def _unescape(text: str) -> str:
    try:
        raw = codecs.decode(text.encode("latin-1", "backslashreplace"), "unicode_escape")
        return raw.encode("latin-1").decode("utf-8", errors="replace")
    except (UnicodeError, ValueError):
        return text


def _join(base: str | None, path: str) -> str:
    if not path.startswith("/") and base:
        path = os.path.join(base, path)
    return os.path.normpath(path) if path.startswith("/") else path


@dataclass(slots=True)
class Call:
    pid: int
    name: str
    args: str
    ok: bool
    errno: str | None
    returned_path: str | None


def parse_line(line: str, pid: int) -> Call | None:
    match = LINE.match(line.rstrip("\n"))
    if match is None:
        return None
    rest = match.group("rest").strip()
    ret = match.group("ret")
    ok = not ret.startswith("-") or ret == "?"
    errno = None
    if ret.startswith("-"):
        found = ERRNO.match(rest)
        errno = found.group("errno") if found else "EUNKNOWN"
    returned = RETURN_PATH.match(rest)
    return Call(
        pid=pid,
        name=match.group("name"),
        args=match.group("args"),
        ok=ok,
        errno=errno,
        returned_path=returned.group("path") if returned else None,
    )


def _strings(args: str) -> list[str]:
    return [_unescape(s) for s in STRING.findall(args)]


def _paths_with_bases(args: str) -> list[str]:
    """Each quoted path in ``args``, joined with the directory descriptor just before it."""
    paths: list[str] = []
    for match in STRING.finditer(args):
        before = args[: match.start()].rstrip(", ")
        start = max(before.rfind(", "), before.rfind("(")) + 1 if before else 0
        previous = before[start:].strip()
        base = BASE_DIR.match(previous)
        paths.append(_join(base.group("dir") if base else None, _unescape(match.group(1))))
    return paths


@dataclass(slots=True)
class Collector:
    """Merges identical events and counts every syscall."""

    cap: int = DEFAULT_EVENT_CAP
    events: list[Event] = field(default_factory=list)
    syscalls: Counter[str] = field(default_factory=Counter)
    truncated: bool = False
    _index: dict[tuple[object, ...], Event] = field(default_factory=dict)

    def add(self, pid: int, syscall: str, kind: str, op: Op, result: str, **fields: object) -> None:
        key = (kind, op, result, *sorted(fields.items()))
        found = self._index.get(key)
        if found is not None:
            found.count += 1
            return
        if len(self.events) >= self.cap:
            self.truncated = True
            return
        event = Event(
            id=f"e{len(self.events) + 1}",
            kind=kind,  # type: ignore[arg-type]
            op=op,
            result=result,
            syscall=syscall,
            pid=pid,
            **fields,  # type: ignore[arg-type]
        )
        self.events.append(event)
        self._index[key] = event

    def call(self, call: Call) -> None:
        self.syscalls[call.name] += 1
        result = "ok" if call.ok else (call.errno or "EUNKNOWN")
        name, args = call.name, call.args
        if name in OPEN_CALLS:
            self._open(call, result)
        elif name in EXEC_CALLS:
            paths = _paths_with_bases(args)
            if paths:
                self.add(call.pid, name, "exec", "exec", result, path=paths[0])
        elif name in READDIR_CALLS:
            fd = FD_PATH.match(args)
            if fd and call.ok:
                self.add(call.pid, name, "file", "readdir", result, path=fd.group("path"))
        elif name in CREATE_CALLS:
            paths = _paths_with_bases(args)
            if paths:  # symlink(target, linkpath): the new entry is the last path
                self.add(call.pid, name, "file", "create", result, path=paths[-1])
        elif name in DELETE_CALLS:
            for path in _paths_with_bases(args)[:1]:
                self.add(call.pid, name, "file", "delete", result, path=path)
        elif name in RENAME_CALLS:
            paths = _paths_with_bases(args)
            if len(paths) >= 2:
                self.add(call.pid, name, "file", "rename-from", result, path=paths[0])
                self.add(call.pid, name, "file", "rename-to", result, path=paths[1])
        elif name == "truncate":
            for path in _paths_with_bases(args)[:1]:
                self.add(call.pid, name, "file", "truncate", result, path=path)
        elif name in NET_CALLS:
            self._net(call, result, NET_CALLS[name])

    def _open(self, call: Call, result: str) -> None:
        paths = _paths_with_bases(call.args)
        if not paths:
            return
        requested = paths[0]
        flags = call.args
        if "O_PATH" in flags:
            return  # an O_PATH descriptor needs no access right
        path = call.returned_path if call.ok and call.returned_path else requested
        extra: dict[str, object] = {"path": path}
        if requested != path:
            extra["requested"] = requested
        if call.name == "creat" or "O_CREAT" in flags:
            self.add(call.pid, call.name, "file", "create", result, **extra)
        elif any(flag in flags for flag in WRITE_FLAGS) or "O_TRUNC" in flags:
            self.add(call.pid, call.name, "file", "write", result, **extra)
        elif "O_DIRECTORY" in flags:
            self.add(call.pid, call.name, "file", "readdir", result, **extra)
        else:
            self.add(call.pid, call.name, "file", "read", result, **extra)

    def _net(self, call: Call, result: str, op: str) -> None:
        kind = SOCKET_KIND.match(call.args)
        unix = SUN_PATH.search(call.args)
        port = PORT.search(call.args)
        if unix:
            address = ("@" if unix.group("abstract") else "") + _unescape(unix.group("path"))
            self.add(call.pid, call.name, "net", op, result, protocol="unix", address=address)  # type: ignore[arg-type]
            return
        if port is None:
            return  # a send on a connected socket names no address
        protocol = "udp" if kind and kind.group("kind") == "UDP" else "tcp"
        if kind is None and call.name in ("sendto", "sendmsg", "sendmmsg"):
            protocol = "udp"
        found = ADDR4.search(call.args) or ADDR6.search(call.args)
        self.add(
            call.pid,
            call.name,
            "net",
            op,  # type: ignore[arg-type]
            result,
            protocol=protocol,
            port=int(port.group("port")),
            address=found.group("addr") if found else None,
        )


def read_trace_dir(directory: Path, cap: int = DEFAULT_EVENT_CAP) -> tuple[Collector, list[int]]:
    """Parse every ``trace.<pid>`` file. Returns the events and the pids, lowest first."""
    collector = Collector(cap=cap)
    files: list[tuple[int, Path]] = []
    for path in directory.glob("trace.*"):
        try:
            files.append((int(path.suffix[1:]), path))
        except ValueError:
            continue
    files.sort()
    for pid, path in files:
        pending: str | None = None
        with path.open(errors="replace") as handle:
            for raw in handle:
                line = raw.rstrip("\n")
                unfinished = UNFINISHED.match(line)
                if unfinished:
                    pending = unfinished.group("head")
                    continue
                resumed = RESUMED.match(line)
                if resumed and pending is not None:
                    line = pending + resumed.group("tail")
                    pending = None
                call = parse_line(line, pid)
                if call is not None:
                    collector.call(call)
    return collector, [pid for pid, _ in files]
