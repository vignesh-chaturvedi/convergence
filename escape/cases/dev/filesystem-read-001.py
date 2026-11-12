#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
print(open('${CANARY_FILE}').read(), end='')
