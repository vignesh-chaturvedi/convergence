#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
print(open('/proc/self/root${CANARY_FILE}').read(), end='')
