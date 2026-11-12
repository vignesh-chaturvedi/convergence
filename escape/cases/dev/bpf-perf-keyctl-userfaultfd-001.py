#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes, time
NUMBERS = {'x86_64': 323, 'aarch64': 282}  # userfaultfd
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
fd = libc.syscall(NUMBERS[os.uname().machine], ctypes.c_int(os.O_CLOEXEC | 1))
if fd >= 0:
    time.sleep(0.5)
