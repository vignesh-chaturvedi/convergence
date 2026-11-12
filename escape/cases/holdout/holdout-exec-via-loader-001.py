#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

fd = os.open("${MARKER}", os.O_RDONLY)
os.set_inheritable(fd, True)
path = f"/proc/self/fd/{fd}"
reached()
os.execv("${LOADER}", ["${LOADER}", path, "1"])
