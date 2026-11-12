#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
print(os.environ['${ENV_CANARY_NAME}'])
