#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


link = os.path.join('${OUT_DIR}', 'proc-link')
os.symlink(os.path.join('/proc/self/cwd', os.path.relpath('${CANARY_FILE}', '${WORKDIR}')), link)
reached()
print(open(link).read(), end='')
