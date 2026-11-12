#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


path = os.path.join(os.getcwd(), os.path.relpath('${CANARY_FILE}', '${WORKDIR}'))
reached()
print(open(path).read(), end='')
