#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
os.kill(int('${SENTINEL_PID}'), 10)
