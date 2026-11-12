#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = ctypes.create_string_buffer(120)  # struct io_uring_params, zeroed
reached()
fd = libc.syscall(425, ctypes.c_uint(4), params)  # io_uring_setup on x86_64 and arm64
if fd >= 0:
    time.sleep(0.5)
