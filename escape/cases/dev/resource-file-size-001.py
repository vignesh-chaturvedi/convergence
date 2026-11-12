#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
with open(os.path.join('${OUT_DIR}', 'large.bin'), 'wb') as f:
    f.write(b'X' * (2 * 1024 * 1024))
