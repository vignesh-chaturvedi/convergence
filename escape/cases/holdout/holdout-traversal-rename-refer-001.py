#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import ctypes, os, platform
source = os.path.join("${OUT_DIR}", "rename-source")
open(source, "w").write("marker")
number = {"x86_64": 316, "aarch64": 276}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
result = libc.syscall(number, -100, os.fsencode(source), -100,
                      os.fsencode("${FORBIDDEN_PATH}"), 1)
if result < 0:
    raise OSError(ctypes.get_errno(), "renameat2 failed")
