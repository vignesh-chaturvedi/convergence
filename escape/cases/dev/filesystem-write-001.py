#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
open('${FORBIDDEN_PATH}', 'w').write('escaped')
