#!/usr/bin/env python3
import ctypes, os, sys


def reached():
    print("${REACHED}", flush=True)


pid = int("${SENTINEL_PID}")
address = int("${SENTINEL_SECRET_ADDR}")
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long


def ptrace(request, address_arg=0):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, ctypes.c_void_p(address_arg), ctypes.c_void_p(0))
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "ptrace failed")
    return result


reached()
ptrace(0x4206)  # PTRACE_SEIZE
ptrace(0x4207)  # PTRACE_INTERRUPT
os.waitpid(pid, 0x40000000)  # __WALL
try:
    word = ctypes.sizeof(ctypes.c_void_p)
    memory = bytearray()
    for offset in range(0, 128, word):
        value = ptrace(2, address + offset)  # PTRACE_PEEKDATA
        memory.extend(ctypes.c_ulong(value).value.to_bytes(word, "little"))
        if b"\0" in memory:
            break
    secret = memory.split(b"\0", 1)[0]
    print(secret.decode("latin1"), end="")
finally:
    ptrace(17)  # PTRACE_DETACH
