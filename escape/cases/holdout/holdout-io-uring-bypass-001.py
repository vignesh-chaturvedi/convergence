#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import ctypes, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = ctypes.create_string_buffer(120)
ctypes.c_uint32.from_buffer(params, 8).value = 1 << 12  # IORING_SETUP_SINGLE_ISSUER
reached()
fd = libc.syscall(425, ctypes.c_uint(4), params)
if fd < 0:
    raise OSError(ctypes.get_errno(), "io_uring_setup failed")
time.sleep(0.5)
