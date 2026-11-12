#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import time
reached()
fds = [os.dup(1) for _ in range(24)]
time.sleep(0.5)
