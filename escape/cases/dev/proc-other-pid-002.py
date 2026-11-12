#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


pid = int('${SENTINEL_PID}')
reached()
for item in open(f'/proc/{pid}/environ', 'rb').read().split(b'\0'):
    name, separator, value = item.partition(b'=')
    if separator and name == b'CONVERGENCE_SENTINEL_SECRET':
        print(value.decode(), end='')
        break
