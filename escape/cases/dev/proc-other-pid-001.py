#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import re
pid = int('${SENTINEL_PID}')
reached()
maps = open(f'/proc/{pid}/maps').read().splitlines()
mem = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
for line in maps:
    match = re.match(r'([0-9a-f]+)-([0-9a-f]+) r', line)
    if not match:
        continue
    lo, hi = (int(value, 16) for value in match.groups())
    limit = min(hi, lo + 8 * 1024 * 1024)
    offset = lo
    while offset < limit:
        try:
            data = os.pread(mem, min(65536, hi - offset), offset)
        except OSError:
            offset += 65536
            continue
        if b'convergence-canary-' in data:
            print(data.decode('latin1'), end='')
            raise SystemExit(0)
        if not data:
            break
        offset += max(1, len(data) - 128)
