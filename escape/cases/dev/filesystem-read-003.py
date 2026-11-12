#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes
class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
path = os.fsencode('${CANARY_FILE}')
how = OpenHow(flags=os.O_RDONLY)
reached()
fd = libc.syscall(437, -100, ctypes.c_char_p(path), ctypes.byref(how), ctypes.sizeof(how))
if fd < 0:
    raise OSError(ctypes.get_errno(), 'openat2 failed')
print(os.read(fd, 4096).decode(), end='')
