#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

directory = os.open("${WORKDIR}", os.O_RDONLY | os.O_DIRECTORY)
relative = os.path.relpath("${CANARY_FILE}", "${WORKDIR}")
reached()
fd = os.open(relative, os.O_RDONLY, dir_fd=directory)
print(os.read(fd, 4096).decode(), end="")
