#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
os.unlink('${SENTINEL_FILE}')
