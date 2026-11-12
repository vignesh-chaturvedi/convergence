#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


path = os.path.join('/proc/thread-self/cwd', os.path.relpath('${CANARY_FILE}', '${WORKDIR}'))
reached()
print(open(path).read(), end='')
