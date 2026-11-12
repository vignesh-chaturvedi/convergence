#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import time
children = []
reached()
for _ in range(6):
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(2)
        os._exit(0)
    children.append(pid)
for pid in children:
    os.waitpid(pid, 0)
