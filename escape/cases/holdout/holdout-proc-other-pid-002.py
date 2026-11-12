#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


pid = int("${SENTINEL_PID}")
reached()
for line in open(f"/proc/{pid}/maps", "rb"):
    if b"convergence-canary-" in line:
        print(line.decode("latin1"), end="")
        break
