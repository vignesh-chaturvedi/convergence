"""ctypes binding to libseccomp, used to *build* seccomp-bpf filters.

Filters are compiled by libseccomp in the supervising process and exported as classic BPF.
The child that is about to exec only installs the finished program with one ``prctl``, so no
library code runs between fork and exec. libseccomp handles architecture checks (for
example x32 and 32-bit compat syscalls on x86_64), so they are not hand-written here.

Constants follow ``include/seccomp.h.in`` of libseccomp v2.5.5, the version Ubuntu 24.04
ships. Only the stable, non-variadic parts of the API are bound.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import enum
import os
from dataclasses import dataclass
from functools import cache
from types import TracebackType

from convergence.kernel._libc import PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prctl

# Filter actions (SCMP_ACT_*).
ACT_KILL_PROCESS = 0x80000000
ACT_KILL_THREAD = 0x00000000
ACT_TRAP = 0x00030000
ACT_LOG = 0x7FFC0000
ACT_ALLOW = 0x7FFF0000


def act_errno(err: int) -> int:
    """SCMP_ACT_ERRNO(err): fail the syscall with ``err`` without running it."""
    return 0x00050000 | (err & 0x0000FFFF)


class Compare(enum.IntEnum):
    """enum scmp_compare."""

    NE = 1
    LT = 2
    LE = 3
    EQ = 4
    GE = 5
    GT = 6
    MASKED_EQ = 7


class FilterAttr(enum.IntEnum):
    """enum scmp_filter_attr (the subset used here)."""

    ACT_DEFAULT = 1
    ACT_BADARCH = 2
    CTL_NNP = 3


class _ScmpVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_uint),
        ("minor", ctypes.c_uint),
        ("micro", ctypes.c_uint),
    ]


class ArgCmp(ctypes.Structure):
    """struct scmp_arg_cmp: compare syscall argument ``arg`` (0-5) using ``op``."""

    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


class _SockFprog(ctypes.Structure):
    """struct sock_fprog from include/uapi/linux/filter.h."""

    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


BPF_INSTRUCTION_SIZE = 8  # struct sock_filter: __u16 code; __u8 jt; __u8 jf; __u32 k

_NR_SCMP_ERROR = -1  # __NR_SCMP_ERROR: libseccomp does not know the name


class SyscallKind(enum.StrEnum):
    NATIVE = "native"  # exists on this architecture
    OTHER_ARCH = "other-architecture"  # libseccomp knows it, but not on this architecture
    UNKNOWN = "unknown"  # libseccomp does not know the name (too new, or a typo)


@dataclass(frozen=True, slots=True)
class SyscallLookup:
    name: str
    number: int | None
    kind: SyscallKind


class SeccompUnavailable(Exception):
    """libseccomp could not be loaded, or the kernel lacks seccomp filtering."""


@dataclass(frozen=True, slots=True)
class LibraryInfo:
    path: str
    version: tuple[int, int, int]
    api_level: int


class Library:
    """A loaded libseccomp with explicit function signatures."""

    def __init__(self, path: str) -> None:
        self.path = path
        lib = ctypes.CDLL(path, use_errno=True)

        lib.seccomp_version.restype = ctypes.POINTER(_ScmpVersion)
        lib.seccomp_version.argtypes = []
        lib.seccomp_api_get.restype = ctypes.c_uint
        lib.seccomp_api_get.argtypes = []
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_release.restype = None
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
        lib.seccomp_attr_set.restype = ctypes.c_int
        lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_rule_add_array.restype = ctypes.c_int
        lib.seccomp_rule_add_array.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(ArgCmp),
        ]
        lib.seccomp_export_bpf.restype = ctypes.c_int
        lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._lib = lib

    def info(self) -> LibraryInfo:
        v = self._lib.seccomp_version().contents
        return LibraryInfo(
            path=self.path,
            version=(int(v.major), int(v.minor), int(v.micro)),
            api_level=int(self._lib.seccomp_api_get()),
        )

    def lookup(self, name: str) -> SyscallLookup:
        """Classify ``name``: native here, a syscall of another architecture, or unknown.

        libseccomp returns -1 for names it does not know at all, and negative "pseudo"
        numbers for syscalls that exist only on other architectures. A rule for a pseudo
        syscall is accepted and has no effect on this architecture.
        """
        number = int(self._lib.seccomp_syscall_resolve_name(name.encode()))
        if number == _NR_SCMP_ERROR:
            return SyscallLookup(name, None, SyscallKind.UNKNOWN)
        if number < 0:
            return SyscallLookup(name, number, SyscallKind.OTHER_ARCH)
        return SyscallLookup(name, number, SyscallKind.NATIVE)

    def resolve_syscall(self, name: str) -> int:
        """The number libseccomp uses for ``name``. Raises ``KeyError`` if it is unknown."""
        found = self.lookup(name)
        if found.number is None:
            raise KeyError(f"libseccomp does not know the syscall {name!r}")
        return found.number

    def new_filter(self, default_action: int) -> Filter:
        return Filter(self, default_action)


def _check(ret: int, what: str) -> None:
    # libseccomp returns negative errno values instead of setting errno.
    if ret < 0:
        raise OSError(-ret, f"{what}: {os.strerror(-ret)}")


class Filter:
    """A libseccomp filter context for the native architecture.

    Other architectures are not added, so a syscall made through a foreign ABI (for example
    i386 ``int 0x80`` on x86_64) hits the bad-architecture action, which is set to kill the
    process.
    """

    def __init__(self, library: Library, default_action: int) -> None:
        self._library = library
        self._lib = library._lib
        ctx = self._lib.seccomp_init(ctypes.c_uint32(default_action))
        if not ctx:
            raise SeccompUnavailable("seccomp_init failed")
        self._ctx: int | None = int(ctx)
        # The child sets no_new_privs itself; libseccomp never loads this filter.
        _check(
            int(self._lib.seccomp_attr_set(self._ctx, FilterAttr.CTL_NNP, 0)),
            "seccomp_attr_set(CTL_NNP)",
        )
        _check(
            int(self._lib.seccomp_attr_set(self._ctx, FilterAttr.ACT_BADARCH, ACT_KILL_PROCESS)),
            "seccomp_attr_set(ACT_BADARCH)",
        )

    def _require_ctx(self) -> int:
        if self._ctx is None:
            raise ValueError("filter already released")
        return self._ctx

    def add_rule(self, action: int, syscall: str, *conditions: ArgCmp) -> None:
        """Apply ``action`` to ``syscall`` when every condition matches."""
        number = self._library.resolve_syscall(syscall)
        array = (ArgCmp * len(conditions))(*conditions) if conditions else None
        _check(
            int(
                self._lib.seccomp_rule_add_array(
                    self._require_ctx(),
                    ctypes.c_uint32(action),
                    number,
                    len(conditions),
                    array,
                )
            ),
            f"seccomp_rule_add({syscall})",
        )

    def export_bpf(self) -> bytes:
        """Compile the filter to a classic BPF program."""
        fd = os.memfd_create("convergence-seccomp", os.MFD_CLOEXEC)
        try:
            _check(int(self._lib.seccomp_export_bpf(self._require_ctx(), fd)), "seccomp_export_bpf")
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, 0, os.SEEK_SET)
            program = b""
            while len(program) < size:
                chunk = os.read(fd, size - len(program))
                if not chunk:
                    break
                program += chunk
        finally:
            os.close(fd)
        if len(program) == 0 or len(program) % BPF_INSTRUCTION_SIZE:
            raise SeccompUnavailable(f"exported BPF program has invalid size {len(program)}")
        return program

    def release(self) -> None:
        if self._ctx is not None:
            self._lib.seccomp_release(self._ctx)
            self._ctx = None

    def __enter__(self) -> Filter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


@cache
def library() -> Library:
    """Load libseccomp, or raise :class:`SeccompUnavailable`."""
    candidates: list[str] = []
    found = ctypes.util.find_library("seccomp")
    if found:
        candidates.append(found)
    candidates.append("libseccomp.so.2")
    errors: list[str] = []
    for candidate in candidates:
        try:
            return Library(candidate)
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
    raise SeccompUnavailable("libseccomp could not be loaded (" + "; ".join(errors) + ")")


def install_program(program: bytes) -> None:
    """Install a classic BPF program on the calling thread.

    The thread must already have ``no_new_privs`` set. Once installed, the filter cannot be
    removed, and it is inherited by children and kept across execve.
    """
    count, rem = divmod(len(program), BPF_INSTRUCTION_SIZE)
    if rem or not 0 < count <= 0xFFFF:
        raise ValueError(f"invalid BPF program size {len(program)}")
    buf = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len=count, filter=ctypes.addressof(buf))
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog))
