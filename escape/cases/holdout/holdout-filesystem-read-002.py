#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import os
reached()
directory = os.open("${CANARY_DIR}", os.O_RDONLY | os.O_DIRECTORY)
name = os.path.basename("${CANARY_FILE}")
fd = os.open(name, os.O_RDONLY, dir_fd=directory)
print(os.read(fd, 4096).decode(), end="")
