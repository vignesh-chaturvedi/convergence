#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


path = os.path.join('${CANARY_DIR}', os.path.basename('${CANARY_FILE}'))
reached()
print(open(path).read(), end='')
