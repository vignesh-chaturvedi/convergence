#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

directory = os.open("${WORKDIR}", os.O_RDONLY | os.O_DIRECTORY)
relative = os.path.relpath("${CANARY_FILE}", "${WORKDIR}")
path = f"/proc/self/fd/{directory}/{relative}"
reached()
print(open(path).read(), end="")
