#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

reached()
os.posix_spawn("/usr/bin/sleep", ["sleep", "3"], os.environ.copy(), setsid=True)
os._exit(0)
