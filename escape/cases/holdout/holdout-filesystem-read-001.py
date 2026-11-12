#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import mmap
reached()
fd = os.open("${CANARY_FILE}", os.O_RDONLY)
with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as view:
    print(view[:].decode(), end="")
