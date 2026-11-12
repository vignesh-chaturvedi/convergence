#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


link = os.path.join('${OUT_DIR}', 'hardlink')
reached()
os.link('${CANARY_FILE}', link)
print(open(link).read(), end='')
