#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


fd = os.open('${MARKER}', os.O_RDONLY)
reached()
os.execve(fd, ['sleep', '1'], os.environ.copy())
