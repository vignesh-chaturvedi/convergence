#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import time
reached()
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork():
        os._exit(0)
    time.sleep(3)
    os._exit(0)
os.waitpid(pid, 0)
