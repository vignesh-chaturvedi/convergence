#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


link = os.path.join('${OUT_DIR}', 'outside-link')
os.symlink('${CANARY_DIR}', link)
reached()
open(os.path.join(link, os.path.basename('${FORBIDDEN_PATH}')), 'w').write('escaped')
