#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import time
reached()
end = time.process_time() + 2.5
x = 1
while time.process_time() < end:
    x = (x * 3) % 1000000007
