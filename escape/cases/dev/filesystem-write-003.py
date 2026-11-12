#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


target = os.path.join('${OUT_DIR}', 'link-target')
open(target, 'w').write('marker')
reached()
os.symlink(target, '${FORBIDDEN_PATH}')
