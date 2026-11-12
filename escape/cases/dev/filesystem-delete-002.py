#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
os.rename('${SENTINEL_FILE}', os.path.join('${OUT_DIR}', 'moved'))
