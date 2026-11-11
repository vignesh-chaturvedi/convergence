"""Shared libc access: raw system calls, ``prctl``, and errno handling."""

from __future__ import annotations

import ctypes
import os
from functools import cache

# prctl(2) options, from include/uapi/linux/prctl.h.
PR_GET_SECCOMP = 21
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

# include/uapi/linux/seccomp.h
SECCOMP_MODE_FILTER = 2


@cache
def libc() -> ctypes.CDLL:
    """The C library of the running process, with errno capture enabled."""
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    lib.prctl.restype = ctypes.c_int
    lib.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    return lib


def raise_errno(what: str) -> None:
    """Raise :class:`OSError` for the errno left by the last libc call."""
    err = ctypes.get_errno()
    raise OSError(err, f"{what}: {os.strerror(err)}")


def syscall(number: int, *args: object) -> int:
    """Invoke a raw system call, raising :class:`OSError` on failure.

    Arguments must already be ctypes values (or ``None`` for a NULL pointer) so that their
    widths are explicit.
    """
    ret = int(libc().syscall(ctypes.c_long(number), *args))
    if ret < 0:
        raise_errno(f"syscall {number}")
    return ret


def prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    """Call prctl(2), raising :class:`OSError` on failure."""
    ret = int(libc().prctl(option, arg2, arg3, arg4, arg5))
    if ret < 0:
        raise_errno(f"prctl({option})")
    return ret


def set_no_new_privs() -> None:
    """Set ``no_new_privs`` for the calling thread. It can never be cleared again."""
    prctl(PR_SET_NO_NEW_PRIVS, 1)


def get_no_new_privs() -> bool:
    return prctl(PR_GET_NO_NEW_PRIVS) == 1
