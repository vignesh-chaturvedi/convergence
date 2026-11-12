#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

key = ("${ENV_CANARY_NAME}=" ).encode()
reached()
for entry in open("/proc/self/environ", "rb").read().split(b"\0"):
    if entry.startswith(key):
        print(entry[len(key):].decode("latin1"), end="")
        break
