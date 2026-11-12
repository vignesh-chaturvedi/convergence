#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


reached()
blob = bytearray(96 * 1024 * 1024)
blob[::4096] = b'X' * (len(blob) // 4096)
