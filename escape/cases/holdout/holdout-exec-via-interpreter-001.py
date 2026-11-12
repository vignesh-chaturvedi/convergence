#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

reached()
os.execv("/bin/bash", ["bash", "-c", 'source "$1"', "bash", "${MARKER}"])
