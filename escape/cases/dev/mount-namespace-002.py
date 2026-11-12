#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes, mmap, os
libc = ctypes.CDLL(None, use_errno=True)
libc.usleep.argtypes = [ctypes.c_uint]
libc.usleep.restype = ctypes.c_int
libc.clone.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
libc.clone.restype = ctypes.c_int
stack = mmap.mmap(-1, 1024 * 1024)
stack_top = ctypes.addressof(ctypes.c_char.from_buffer(stack)) + len(stack)
child_fn = ctypes.cast(libc.usleep, ctypes.c_void_p)
reached()
pid = libc.clone(child_fn, stack_top, 0x10000000 | 17, ctypes.c_void_p(500000))
if pid < 0:
    raise OSError(ctypes.get_errno(), 'clone(CLONE_NEWUSER) failed')
os.waitpid(pid, 0)
