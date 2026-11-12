#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

source = os.path.join("${OUT_DIR}", "source-link")
target = os.path.join("${OUT_DIR}", "linked-secret")
os.symlink("${CANARY_FILE}", source)
reached()
os.link(source, target, follow_symlinks=True)
print(open(target).read(), end="")
