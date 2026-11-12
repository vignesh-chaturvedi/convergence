"""Turning strace output into attributed denials (ADR 0007).

Only failed calls with an errno a sandbox can cause, and the two rlimit signals, are read.
Each is attributed to the mechanism that must have caused it, or recorded as
``unattributed``. Nothing is guessed: ``EACCES`` on a path inside a grant is most likely
file permissions, so it stays unattributed.
"""

from __future__ import annotations

import codecs
import os
import re
from dataclasses import dataclass
from pathlib import Path

from convergence.runtime.record import Denial

COLLECTED_ERRNOS = frozenset({"EACCES", "EPERM", "EXDEV", "EAGAIN", "EMFILE", "EFBIG", "ENOMEM"})

# Path-based calls Landlock controls (security/landlock/fs.c hooks).
PATH_CALLS = frozenset(
    {
        "open", "openat", "openat2", "creat", "execve", "execveat", "truncate",
        "mkdir", "mkdirat", "mknod", "mknodat", "unlink", "unlinkat", "rmdir",
        "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
    }
)  # fmt: skip
WRITE_CALLS = PATH_CALLS - {"open", "openat", "openat2", "execve", "execveat"}
EXEC_CALLS = frozenset({"execve", "execveat"})
SECOND_PATH_CALLS = frozenset({"symlink", "symlinkat"})  # the first string is link content
TWO_PATH_CALLS = frozenset({"rename", "renameat", "renameat2", "link", "linkat"})
FORK_CALLS = frozenset({"fork", "vfork", "clone", "clone3"})
MEMORY_CALLS = frozenset({"mmap", "mremap", "brk"})
NETWORK_CALLS = frozenset({"connect", "bind", "sendto", "sendmsg", "sendmmsg"})
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

SYSCALL_LINE = re.compile(
    r"^(?P<name>[a-z_0-9]+)\((?P<args>.*)\)\s+=\s+-1\s+(?P<errno>E[A-Z0-9]+)\b"
)
SIGNAL_LINE = re.compile(r"^--- (?P<signal>SIG[A-Z0-9]+) ")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
DIRFD = re.compile(r"(?:AT_FDCWD|\d+)<(?P<dir>[^>]*)>")
PORT = re.compile(r"sin6?_port=htons\((?P<port>\d+)\)")
SOCKET_PROTOCOL = re.compile(r"^\d+<(?P<protocol>TCP|UDP)(?:v6)?:")
MAX_LINE = 300


@dataclass(frozen=True, slots=True)
class Context:
    """What attribution needs to know about the policy that was applied."""

    denied_syscalls: frozenset[str]  # the built-in list and the policy's deny list
    argument_rules: frozenset[str]  # syscalls denied only for some argument values
    allow_list: frozenset[str] | None  # allow-list mode: the allowed names
    grants: dict[str, tuple[str, ...]]  # bucket -> real paths granted
    limits: frozenset[str]  # names of the resources.* limits that are set


def _unescape(text: str) -> str:
    try:
        raw = codecs.decode(text.encode("latin-1", "backslashreplace"), "unicode_escape")
        return raw.encode("latin-1").decode("utf-8", errors="replace")
    except (UnicodeError, ValueError):
        return text


def _paths(name: str, args: str) -> list[str]:
    strings = [_unescape(s) for s in STRING.findall(args)]
    if name in SECOND_PATH_CALLS:
        strings = strings[1:2]
    elif name in TWO_PATH_CALLS:
        strings = strings[:2]
    else:
        strings = strings[:1]
    dirs = [m.group("dir") for m in DIRFD.finditer(args)]
    paths: list[str] = []
    for index, path in enumerate(strings):
        if not path.startswith("/"):
            base = dirs[index] if index < len(dirs) else (dirs[0] if dirs else "")
            path = os.path.join(base, path) if base else path
        paths.append(os.path.normpath(path))
    return paths


def _inside(path: str, roots: tuple[str, ...]) -> bool:
    for root in roots:
        stripped = root.rstrip("/") or "/"
        if path == stripped or path.startswith(stripped.rstrip("/") + "/"):
            return True
    return False


def _same_filesystem(first: str, second: str) -> bool:
    try:
        return os.stat(os.path.dirname(first)).st_dev == os.stat(os.path.dirname(second)).st_dev
    except OSError:
        return False


def _bucket(name: str, args: str) -> str:
    if name in EXEC_CALLS:
        return "execute"
    if name in WRITE_CALLS or any(flag in args for flag in WRITE_FLAGS):
        return "write"
    return "read"


def _filesystem(name: str, args: str, context: Context) -> tuple[str, str, str]:
    bucket = _bucket(name, args)
    paths = _paths(name, args)
    target = " -> ".join(paths)
    allowed = context.grants.get(bucket, ())
    if bucket == "read":  # every bucket grants read
        allowed = tuple(p for b in ("read", "write", "execute") for p in context.grants.get(b, ()))
    real = []
    for path in paths:
        try:
            real.append(str(Path(path).resolve()))
        except (OSError, RuntimeError):
            real.append(path)
    if paths and all(_inside(p, allowed) for p in real):
        return "unattributed", f"filesystem.{bucket}", target  # inside a grant: permissions
    return "landlock-filesystem", f"filesystem.{bucket}", target


def _network(name: str, args: str) -> tuple[str, str]:
    protocol = SOCKET_PROTOCOL.match(args)
    port = PORT.search(args)
    kind = (protocol.group("protocol") if protocol else "TCP").lower()
    if name == "bind":
        rule = f"network.{kind}_bind"
    else:
        rule = "network.tcp_connect" if kind == "tcp" else "network.udp_send"
    return rule, f"port {port.group('port')}" if port else ""


def attribute_line(line: str, pid: int, context: Context) -> Denial | None:
    line = line.rstrip("\n")
    signal_match = SIGNAL_LINE.match(line)
    if signal_match:
        sig = signal_match.group("signal")
        by_signal = {"SIGXCPU": "resources.cpu_seconds", "SIGXFSZ": "resources.max_file_size_mb"}
        if sig in by_signal:
            return Denial(pid, sig, "", "rlimit", by_signal[sig], "", line[:MAX_LINE])
        return None
    match = SYSCALL_LINE.match(line)
    if match is None:
        return None
    name, args, err = match.group("name"), match.group("args"), match.group("errno")
    if err not in COLLECTED_ERRNOS:
        return None
    mechanism, rule, target = "unattributed", "", ""
    if err == "EACCES" and name in PATH_CALLS:
        mechanism, rule, target = _filesystem(name, args, context)
    elif err == "EACCES" and name in NETWORK_CALLS:
        mechanism = "landlock-network"
        rule, target = _network(name, args)
    elif err == "EXDEV" and name in TWO_PATH_CALLS:
        paths = _paths(name, args)
        rule, target = "filesystem.write", " -> ".join(paths)
        # A rename across filesystems also fails with EXDEV; only one within a filesystem
        # can be Landlock's REFER check.
        if len(paths) == 2 and _same_filesystem(paths[0], paths[1]):
            mechanism = "landlock-filesystem"
    elif err == "EPERM":
        if name in context.denied_syscalls:
            mechanism, rule = "seccomp", "syscalls (deny list)"
        elif context.allow_list is not None and name not in context.allow_list:
            mechanism, rule = "seccomp", "syscalls.allow"
        elif name in context.argument_rules:
            mechanism, rule = "seccomp", f"syscalls (argument rule on {name})"
    elif err == "EAGAIN" and name in FORK_CALLS and "max_processes" in context.limits:
        mechanism, rule = "rlimit", "resources.max_processes"
    elif err == "EMFILE" and "max_open_files" in context.limits:
        mechanism, rule = "rlimit", "resources.max_open_files"
    elif err == "EFBIG" and "max_file_size_mb" in context.limits:
        mechanism, rule = "rlimit", "resources.max_file_size_mb"
    elif err == "ENOMEM" and name in MEMORY_CALLS:
        for limit in ("memory_mb", "address_space_mb"):
            if limit in context.limits:
                mechanism, rule = "rlimit", f"resources.{limit}"
                break
    if mechanism == "unattributed" and not rule:
        # Ordinary failures nothing in the sandbox explains: EAGAIN on a non-blocking read,
        # EACCES from access(), which Landlock does not control, and the like.
        if err in ("EAGAIN", "ENOMEM", "EXDEV"):
            return None
        if err == "EACCES" and name not in PATH_CALLS | NETWORK_CALLS:
            return None
    return Denial(pid, name, err, mechanism, rule, target, line[:MAX_LINE])


def read_trace(directory: Path, context: Context, limit: int = 500) -> tuple[list[Denial], int]:
    """Attributed denials from strace's per-process files, at most ``limit`` kept."""
    denials: list[Denial] = []
    total = 0
    files = sorted(directory.glob("trace.*"), key=lambda p: int(p.suffix[1:] or 0))
    for path in files:
        try:
            pid = int(path.suffix[1:])
        except ValueError:
            continue
        with path.open(errors="replace") as handle:
            for line in handle:
                denial = attribute_line(line, pid, context)
                if denial is None:
                    continue
                total += 1
                if len(denials) < limit:
                    denials.append(denial)
    return denials, total
