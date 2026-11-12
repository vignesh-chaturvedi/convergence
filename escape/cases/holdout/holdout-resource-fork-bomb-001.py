#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import time
def branch(depth):
    if depth == 0:
        time.sleep(0.5)
        return
    children = []
    for _ in range(2):
        pid = os.fork()
        if pid == 0:
            branch(depth - 1)
            os._exit(0)
        children.append(pid)
    for child in children:
        os.waitpid(child, 0)
reached()
branch(2)
