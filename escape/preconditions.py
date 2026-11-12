"""Host preconditions: behaviour the host itself must allow for a case to be testable.

Some attacks are already prevented by the host before Convergence is involved. On Ubuntu
24.04, for example, AppArmor refuses unprivileged user namespaces, and the kernel refuses
TIOCSTI without CAP_SYS_ADMIN (``dev.tty.legacy_tiocsti = 0``). Such a case cannot escape
even unconfined, so it can say nothing about Convergence. A case lists what it needs in
``requires``; where the host lacks it, the case is reported ``not-testable`` and never
counted as blocked.

Each probe tests the behaviour itself in a throwaway child where it can, rather than
trusting a setting.
"""

from __future__ import annotations

import ctypes
import errno
import os
import socket
import struct
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from convergence.kernel import seccomp as sc
from convergence.probe.child import attempt, run_in_child

Precondition = Literal[
    "unprivileged-userns",
    "userns-create",
    "legacy-tiocsti",
    "raw-socket",
    "setuid-executable",
    "io-uring",
    "userfaultfd",
    "unprivileged-bpf",
    "unprivileged-perf",
]
PRECONDITIONS: tuple[Precondition, ...] = (
    "unprivileged-userns",
    "userns-create",
    "legacy-tiocsti",
    "raw-socket",
    "setuid-executable",
    "io-uring",
    "userfaultfd",
    "unprivileged-bpf",
    "unprivileged-perf",
)


@dataclass(frozen=True, slots=True)
class Availability:
    available: bool
    detail: str


def _unprivileged_userns() -> Availability:
    """Can an unprivileged process create a user namespace and use its capabilities there?

    Creating the namespace is not enough: with AppArmor's userns restriction the namespace is
    created but its capabilities are unusable. So the child also maps its ids and creates a
    mount namespace inside, which needs CAP_SYS_ADMIN in the user namespace.
    """
    uid, gid = os.getuid(), os.getgid()

    def child() -> dict[str, str]:
        result = {"unshare_user": attempt(lambda: os.unshare(os.CLONE_NEWUSER))}
        if result["unshare_user"] != "ok":
            return result
        result["map_ids"] = attempt(
            lambda: (
                Path("/proc/self/setgroups").write_text("deny"),
                Path("/proc/self/uid_map").write_text(f"0 {uid} 1"),
                Path("/proc/self/gid_map").write_text(f"0 {gid} 1"),
            )
        )
        if result["map_ids"] == "ok":
            result["unshare_mount"] = attempt(lambda: os.unshare(os.CLONE_NEWNS))
        return result

    outcome = run_in_child(child)
    if not outcome.ok:
        return Availability(False, f"probe failed: {outcome.error}")
    steps = outcome.result
    if all(steps.get(k) == "ok" for k in ("unshare_user", "map_ids", "unshare_mount")):
        return Availability(True, "unprivileged user namespaces with usable capabilities")
    failed = next(f"{k}: {v}" for k, v in steps.items() if v != "ok")
    return Availability(False, f"unprivileged user namespaces are refused here ({failed})")


def _userns_create() -> Availability:
    """Can an unprivileged process create a user namespace at all?

    Weaker than ``unprivileged-userns``: Ubuntu's AppArmor restriction lets the namespace be
    created but makes its capabilities unusable. A case that only needs the namespace to
    exist (the effect the ``namespace-change`` oracle observes) needs only this.
    """
    outcome = run_in_child(lambda: {"unshare_user": attempt(lambda: os.unshare(os.CLONE_NEWUSER))})
    if not outcome.ok:
        return Availability(False, f"probe failed: {outcome.error}")
    result = outcome.result.get("unshare_user")
    if result == "ok":
        return Availability(True, "an unprivileged process can create a user namespace")
    return Availability(False, f"creating a user namespace is refused here ({result})")


def _syscall_probe(name: str, call: Callable[[ctypes.CDLL, int], int], what: str) -> Availability:
    """Make one raw syscall in a throwaway child; available if it returns a descriptor.

    The number comes from libseccomp, so it is right for the running architecture.
    """
    try:
        number = sc.library().resolve_syscall(name)
    except (sc.SeccompUnavailable, KeyError) as exc:
        return Availability(False, f"cannot resolve {name}: {exc}")
    if number < 0:
        return Availability(False, f"{name} does not exist on this architecture")

    def child() -> dict[str, str]:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        fd = call(libc, number)
        if fd < 0:
            return {"result": errno.errorcode.get(ctypes.get_errno(), "error")}
        os.close(fd)
        return {"result": "ok"}

    outcome = run_in_child(child)
    if not outcome.ok:
        return Availability(False, f"probe failed: {outcome.error}")
    result = outcome.result.get("result")
    if result == "ok":
        return Availability(True, f"an unprivileged process can {what}")
    return Availability(False, f"the host refuses to let an unprivileged process {what} ({result})")


def _io_uring() -> Availability:
    params = ctypes.create_string_buffer(120)  # struct io_uring_params, zeroed

    def call(libc: ctypes.CDLL, nr: int) -> int:
        return int(libc.syscall(ctypes.c_long(nr), ctypes.c_uint(4), params))

    return _syscall_probe("io_uring_setup", call, "create an io_uring")


def _userfaultfd() -> Availability:
    flags = os.O_CLOEXEC | 1  # UFFD_USER_MODE_ONLY: allowed without vm.unprivileged_userfaultfd

    def call(libc: ctypes.CDLL, nr: int) -> int:
        return int(libc.syscall(ctypes.c_long(nr), ctypes.c_int(flags)))

    return _syscall_probe("userfaultfd", call, "create a user-mode-only userfaultfd")


def _unprivileged_bpf() -> Availability:
    # union bpf_attr for BPF_MAP_CREATE: map_type (ARRAY), key_size, value_size, max_entries
    raw = struct.pack("=IIII", 2, 4, 4, 1).ljust(72, b"\0")
    attr = ctypes.create_string_buffer(raw, len(raw))

    def call(libc: ctypes.CDLL, nr: int) -> int:
        return int(libc.syscall(ctypes.c_long(nr), ctypes.c_int(0), attr, ctypes.c_uint(len(raw))))

    return _syscall_probe("bpf", call, "create a BPF map")


def _unprivileged_perf() -> Availability:
    # struct perf_event_attr (PERF_ATTR_SIZE_VER0, 64 bytes): a disabled software CPU-clock
    # counter on this process, user space only (disabled | exclude_kernel | exclude_hv).
    flags = 1 | (1 << 5) | (1 << 6)
    raw = struct.pack("=IIQQQQQ", 1, 64, 0, 0, 0, 0, flags).ljust(64, b"\0")
    attr = ctypes.create_string_buffer(raw, len(raw))

    def call(libc: ctypes.CDLL, nr: int) -> int:
        no_group = ctypes.c_int(-1)
        cloexec = ctypes.c_ulong(8)  # PERF_FLAG_FD_CLOEXEC
        return int(
            libc.syscall(ctypes.c_long(nr), attr, ctypes.c_int(0), no_group, no_group, cloexec)
        )

    return _syscall_probe("perf_event_open", call, "open a perf event")


def _legacy_tiocsti() -> Availability:
    path = Path("/proc/sys/dev/tty/legacy_tiocsti")
    try:
        value = path.read_text().strip()
    except FileNotFoundError:
        return Availability(
            True, "the kernel predates dev.tty.legacy_tiocsti: TIOCSTI is unrestricted"
        )
    except OSError as exc:
        return Availability(False, f"cannot read {path}: {exc}")
    if value == "1":
        return Availability(True, "dev.tty.legacy_tiocsti = 1")
    return Availability(
        False, f"dev.tty.legacy_tiocsti = {value}: TIOCSTI already needs CAP_SYS_ADMIN"
    )


def _raw_socket() -> Availability:
    """Can this uid create the raw socket needed for the raw-network case?"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP):
            pass
    except OSError as exc:
        return Availability(False, f"the host refuses raw sockets ({exc})")
    return Availability(True, "an unprivileged process can create an IPv4 raw socket")


def _setuid_executable() -> Availability:
    """Does a setuid helper actually run with a different effective uid here?

    This starts a real setuid helper (``passwd``, else ``su``) and kills it within about
    0.1 s, before it reads any input. That can still leave a PAM or audit log entry, so the
    result is cached and the probe only runs when a selected case requires it.
    """
    candidates = ("/usr/bin/passwd", "/bin/passwd", "/usr/bin/su", "/bin/su")
    for path in dict.fromkeys(candidates):
        try:
            info = os.stat(path)
        except OSError:
            continue
        if not info.st_mode & 0o4000 or not os.access(path, os.X_OK):
            continue
        try:
            proc = subprocess.Popen(  # noqa: S603 - a fixed system path from the list above
                [path],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            continue
        try:
            for _ in range(10):
                try:
                    for line in Path(f"/proc/{proc.pid}/status").read_text().splitlines():
                        if line.startswith("Uid:"):
                            effective = int(line.split()[2])
                            if effective != os.geteuid():
                                return Availability(True, f"{path} changed effective uid")
                            break
                except (OSError, ValueError, IndexError):
                    pass
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
    return Availability(False, "no available setuid helper changed effective uid")


PROBES: dict[Precondition, Callable[[], Availability]] = {
    "unprivileged-userns": _unprivileged_userns,
    "userns-create": _userns_create,
    "legacy-tiocsti": _legacy_tiocsti,
    "raw-socket": _raw_socket,
    "setuid-executable": _setuid_executable,
    "io-uring": _io_uring,
    "userfaultfd": _userfaultfd,
    "unprivileged-bpf": _unprivileged_bpf,
    "unprivileged-perf": _unprivileged_perf,
}


_CACHE: dict[Precondition, Availability] = {}


def probe(name: Precondition) -> Availability:
    """Probe one precondition, once per process.

    Some probes fork, which is only safe before threads start, so the runner probes what its
    selected cases need up front (see :func:`probe_all`); later calls hit the cache.
    """
    if name not in _CACHE:
        _CACHE[name] = PROBES[name]()
    return _CACHE[name]


def probe_all(names: Iterable[Precondition] = PRECONDITIONS) -> dict[Precondition, Availability]:
    return {name: probe(name) for name in names}
