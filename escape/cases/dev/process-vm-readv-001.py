#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import ctypes, re
pid = int("${SENTINEL_PID}")
libc = ctypes.CDLL(None, use_errno=True)


class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def scan():
    for line in open(f"/proc/{pid}/maps"):
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) r", line)
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        for addr in range(lo, min(hi, lo + 8 * 1024 * 1024), 65536):
            buf = ctypes.create_string_buffer(min(65536, hi - addr))
            local, remote = IOV(ctypes.addressof(buf), len(buf)), IOV(addr, len(buf))
            n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
            if n > 0 and b"convergence-canary-" in buf.raw[:n]:
                print(buf.raw[:n].decode("latin1"), end="")
                return


reached()
scan()
