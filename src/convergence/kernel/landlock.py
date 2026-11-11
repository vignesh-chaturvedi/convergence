"""ctypes binding to the three Landlock system calls.

Constants, structure layouts, and the per-ABI feature table are taken from the kernel's
``include/uapi/linux/landlock.h`` and ``Documentation/userspace-api/landlock.rst`` at
commit 067c5c24cef2 (2026-11-10, v7.4-rc2). See docs/landlock-abi.md.

The binding never assumes that a right is supported: callers ask for the features of the
running ABI with :func:`features_for_abi` and must not hand the kernel bits it does not know
(the kernel rejects unknown bits with ``EINVAL``).
"""

from __future__ import annotations

import ctypes
import enum
import errno
import os
import struct
from dataclasses import dataclass
from types import TracebackType

from convergence.kernel._libc import syscall

# Same numbers on x86_64 (arch/x86/entry/syscalls/syscall_64.tbl) and on arm64, which uses
# the generic table (scripts/syscall.tbl).
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

CREATE_RULESET_VERSION = 1 << 0
CREATE_RULESET_ERRATA = 1 << 1

RULE_PATH_BENEATH = 1
RULE_NET_PORT = 2

# The highest ABI version whose features this module knows. A newer kernel is used at this
# level and the extra features are reported as unused, never guessed at.
KNOWN_MAX_ABI = 12


class AccessFs(enum.IntFlag):
    EXECUTE = 1 << 0
    WRITE_FILE = 1 << 1
    READ_FILE = 1 << 2
    READ_DIR = 1 << 3
    REMOVE_DIR = 1 << 4
    REMOVE_FILE = 1 << 5
    MAKE_CHAR = 1 << 6
    MAKE_DIR = 1 << 7
    MAKE_REG = 1 << 8
    MAKE_SOCK = 1 << 9
    MAKE_FIFO = 1 << 10
    MAKE_BLOCK = 1 << 11
    MAKE_SYM = 1 << 12
    REFER = 1 << 13
    TRUNCATE = 1 << 14
    IOCTL_DEV = 1 << 15
    RESOLVE_UNIX = 1 << 16


class AccessNet(enum.IntFlag):
    BIND_TCP = 1 << 0
    CONNECT_TCP = 1 << 1
    BIND_UDP = 1 << 2
    CONNECT_SEND_UDP = 1 << 3


class Scope(enum.IntFlag):
    ABSTRACT_UNIX_SOCKET = 1 << 0
    SIGNAL = 1 << 1


class Permission(enum.IntFlag):
    NAMESPACE_USE = 1 << 0
    CAPABILITY_USE = 1 << 1


NO_FS = AccessFs(0)
NO_NET = AccessNet(0)
NO_SCOPE = Scope(0)
NO_PERMISSIONS = Permission(0)

# Rights that may be granted on a regular file rather than a directory
# (ACCESS_FILE in security/landlock/fs.c).
FILE_ACCESS = (
    AccessFs.EXECUTE
    | AccessFs.WRITE_FILE
    | AccessFs.READ_FILE
    | AccessFs.TRUNCATE
    | AccessFs.IOCTL_DEV
    | AccessFs.RESOLVE_UNIX
)

_ABI1_FS = (
    AccessFs.EXECUTE
    | AccessFs.WRITE_FILE
    | AccessFs.READ_FILE
    | AccessFs.READ_DIR
    | AccessFs.REMOVE_DIR
    | AccessFs.REMOVE_FILE
    | AccessFs.MAKE_CHAR
    | AccessFs.MAKE_DIR
    | AccessFs.MAKE_REG
    | AccessFs.MAKE_SOCK
    | AccessFs.MAKE_FIFO
    | AccessFs.MAKE_BLOCK
    | AccessFs.MAKE_SYM
)


@dataclass(frozen=True, slots=True)
class AbiAddition:
    """What one Landlock ABI version added, as documented by the kernel."""

    abi: int
    summary: str
    fs: AccessFs = NO_FS
    net: AccessNet = NO_NET
    scope: Scope = NO_SCOPE
    permissions: Permission = NO_PERMISSIONS


ABI_ADDITIONS: tuple[AbiAddition, ...] = (
    AbiAddition(1, "filesystem access rights (execute, read, write, create, remove)", fs=_ABI1_FS),
    AbiAddition(2, "renaming and linking across directories (REFER)", fs=AccessFs.REFER),
    AbiAddition(3, "file truncation (TRUNCATE)", fs=AccessFs.TRUNCATE),
    AbiAddition(
        4,
        "TCP bind and connect by port",
        net=AccessNet.BIND_TCP | AccessNet.CONNECT_TCP,
    ),
    AbiAddition(5, "ioctl on character and block devices (IOCTL_DEV)", fs=AccessFs.IOCTL_DEV),
    AbiAddition(
        6,
        "scoping of abstract unix sockets and signals",
        scope=Scope.ABSTRACT_UNIX_SOCKET | Scope.SIGNAL,
    ),
    AbiAddition(7, "audit logging control flags for restrict_self"),
    AbiAddition(8, "thread synchronisation flag for restrict_self (TSYNC)"),
    AbiAddition(9, "pathname unix socket connections (RESOLVE_UNIX)", fs=AccessFs.RESOLVE_UNIX),
    AbiAddition(
        10,
        "UDP bind and connect/send by port; quiet rule flag",
        net=AccessNet.BIND_UDP | AccessNet.CONNECT_SEND_UDP,
    ),
    AbiAddition(11, "no_new_privs flag for restrict_self"),
    AbiAddition(
        12,
        "namespace use and capability use permissions",
        permissions=Permission.NAMESPACE_USE | Permission.CAPABILITY_USE,
    ),
)

if [a.abi for a in ABI_ADDITIONS] != list(range(1, KNOWN_MAX_ABI + 1)):
    raise ImportError("ABI_ADDITIONS must list every ABI from 1 to KNOWN_MAX_ABI exactly once")


@dataclass(frozen=True, slots=True)
class AbiFeatures:
    """Everything a given ABI version can handle, cumulatively."""

    abi: int
    fs: AccessFs
    net: AccessNet
    scope: Scope
    permissions: Permission


def features_for_abi(abi: int) -> AbiFeatures:
    """The rights available at ``abi``, capped at :data:`KNOWN_MAX_ABI`.

    ABI versions below 1 (Landlock unavailable) yield no rights at all.
    """
    effective = min(abi, KNOWN_MAX_ABI)
    fs, net, scope, perms = AccessFs(0), AccessNet(0), Scope(0), Permission(0)
    for addition in ABI_ADDITIONS:
        if addition.abi <= effective:
            fs |= addition.fs
            net |= addition.net
            scope |= addition.scope
            perms |= addition.permissions
    return AbiFeatures(abi=max(effective, 0), fs=fs, net=net, scope=scope, permissions=perms)


class LandlockUnavailable(Exception):
    """Landlock cannot be used on this kernel."""

    def __init__(self, reason: str, err: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.errno = err


def _unavailable_reason(err: int) -> str:
    if err == errno.ENOSYS:
        return "Landlock is not built into this kernel (ENOSYS)"
    if err == errno.EOPNOTSUPP:
        return "Landlock is built in but not enabled at boot (EOPNOTSUPP; check the lsm= list)"
    return f"landlock_create_ruleset failed: {errno.errorcode.get(err, str(err))}"


def abi_version() -> int:
    """Return the highest ABI version the running kernel supports.

    Raises :class:`LandlockUnavailable` if Landlock is absent or disabled.
    """
    try:
        return syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(CREATE_RULESET_VERSION),
        )
    except OSError as exc:
        err = exc.errno or 0
        raise LandlockUnavailable(_unavailable_reason(err), err) from exc


def errata() -> int | None:
    """Return the bitmask of Landlock errata fixed in this kernel.

    Bit ``N - 1`` set means erratum ``N`` is fixed. Returns ``None`` when the kernel predates
    the errata query (it rejects the flag with ``EINVAL``). Informational only: the kernel
    documentation advises against changing behaviour based on errata.
    """
    try:
        return syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(CREATE_RULESET_ERRATA),
        )
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            return None
        raise


def _ruleset_attr(fs: AccessFs, net: AccessNet, scope: Scope, permissions: Permission) -> bytes:
    """Encode ``struct landlock_ruleset_attr`` truncated after the last field in use.

    Layout (seven ``__u64``): handled_access_fs, handled_access_net, scoped,
    quiet_access_fs, quiet_access_net, quiet_scoped, handled_permissions. Older kernels only
    know a prefix of it, so the size passed is the smallest one covering the fields used.
    """
    full = struct.pack("=7Q", int(fs), int(net), int(scope), 0, 0, 0, int(permissions))
    if permissions:
        return full[:56]
    if scope:
        return full[:24]
    if net:
        return full[:16]
    return full[:8]


class Ruleset:
    """A Landlock ruleset file descriptor.

    Build it (``allow_path``, ``allow_port``) in any process. ``restrict_self`` confines only
    the calling thread and its future children, so it belongs in the child about to exec.
    """

    def __init__(
        self,
        fs: AccessFs = NO_FS,
        net: AccessNet = NO_NET,
        scope: Scope = NO_SCOPE,
        permissions: Permission = NO_PERMISSIONS,
    ) -> None:
        if not (fs or net or scope or permissions):
            raise ValueError("a ruleset must handle at least one access right or scope")
        attr = _ruleset_attr(fs, net, scope, permissions)
        buf = ctypes.create_string_buffer(attr, len(attr))
        self.handled_fs = fs
        self.handled_net = net
        self.scope = scope
        self.permissions = permissions
        self.fd: int = syscall(
            SYS_LANDLOCK_CREATE_RULESET, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0)
        )

    def allow_path(self, path: str | os.PathLike[str], access: AccessFs) -> None:
        """Allow ``access`` beneath ``path`` (a directory) or on ``path`` (a file)."""
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            self.allow_path_fd(fd, access)
        finally:
            os.close(fd)

    def allow_path_fd(self, fd: int, access: AccessFs) -> None:
        # struct landlock_path_beneath_attr is packed: __u64 allowed_access; __s32 parent_fd.
        data = struct.pack("=Qi", int(access), fd)
        buf = ctypes.create_string_buffer(data, len(data))
        syscall(
            SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(self.fd),
            ctypes.c_int(RULE_PATH_BENEATH),
            buf,
            ctypes.c_uint32(0),
        )

    def allow_port(self, port: int, access: AccessNet) -> None:
        """Allow ``access`` (bind and/or connect) for a local or remote port number."""
        if not 0 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        # struct landlock_net_port_attr: __u64 allowed_access; __u64 port.
        data = struct.pack("=QQ", int(access), port)
        buf = ctypes.create_string_buffer(data, len(data))
        syscall(
            SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(self.fd),
            ctypes.c_int(RULE_NET_PORT),
            buf,
            ctypes.c_uint32(0),
        )

    def restrict_self(self, flags: int = 0) -> None:
        """Confine the calling thread. Requires ``no_new_privs`` (or CAP_SYS_ADMIN)."""
        syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(self.fd), ctypes.c_uint32(flags))

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> Ruleset:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
