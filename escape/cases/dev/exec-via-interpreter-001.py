#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
os.execv('/bin/sh', ['/bin/sh', '${MARKER}'])
