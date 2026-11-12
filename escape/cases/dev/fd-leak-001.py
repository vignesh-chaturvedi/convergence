#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
print(os.read(int('${INHERITED_FD}'), 4096).decode(), end='')
