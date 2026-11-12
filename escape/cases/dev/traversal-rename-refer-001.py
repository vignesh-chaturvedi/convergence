#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


source = os.path.join('${OUT_DIR}', 'move-me')
open(source, 'w').write('marker')
reached()
os.rename(source, '${FORBIDDEN_PATH}')
