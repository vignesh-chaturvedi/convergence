#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import ctypes, os, time
class CloneArgs(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("pidfd", ctypes.c_uint64),
                ("child_tid", ctypes.c_uint64), ("parent_tid", ctypes.c_uint64),
                ("exit_signal", ctypes.c_uint64), ("stack", ctypes.c_uint64),
                ("stack_size", ctypes.c_uint64), ("tls", ctypes.c_uint64),
                ("set_tid", ctypes.c_uint64), ("set_tid_size", ctypes.c_uint64),
                ("cgroup", ctypes.c_uint64)]
args = CloneArgs(flags=0x10000000 | 0x00020000, exit_signal=17)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
pid = libc.syscall(435, ctypes.byref(args), ctypes.sizeof(args))
if pid < 0:
    raise OSError(ctypes.get_errno(), "clone3 failed")
if pid == 0:
    time.sleep(0.5)
    os._exit(0)
os.waitpid(pid, 0)
