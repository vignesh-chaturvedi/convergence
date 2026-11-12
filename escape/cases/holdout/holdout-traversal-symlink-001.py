#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

root = os.path.join("${OUT_DIR}", "hop")
final = os.path.join("${OUT_DIR}", "secret-link")
os.symlink("${CANARY_DIR}", root)
os.symlink(os.path.join(root, os.path.basename("${CANARY_FILE}")), final)
reached()
print(open(final).read(), end="")
