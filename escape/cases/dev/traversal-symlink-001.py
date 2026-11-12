#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


link = os.path.join('${OUT_DIR}', 'link')
os.symlink('${CANARY_FILE}', link)
reached()
print(open(link).read(), end='')
