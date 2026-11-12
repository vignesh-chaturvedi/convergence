#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes, time
names = ('flags', 'pidfd', 'child_tid', 'parent_tid', 'exit_signal', 'stack', 'stack_size',
         'tls', 'set_tid', 'set_tid_size', 'cgroup')


class Args(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in names]


args = Args(flags=0x10000000, exit_signal=17)  # CLONE_NEWUSER, SIGCHLD
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
pid = libc.syscall(435, ctypes.byref(args), ctypes.sizeof(args))  # clone3 on x86_64 and arm64
if pid == 0:
    time.sleep(0.5)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
