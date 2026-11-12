#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import time
uid, gid = os.getuid(), os.getgid()
reached()
os.unshare(os.CLONE_NEWUSER)
time.sleep(0.5)
open('/proc/self/setgroups', 'w').write('deny')
open('/proc/self/uid_map', 'w').write(f'0 {uid} 1')
open('/proc/self/gid_map', 'w').write(f'0 {gid} 1')
os.unshare(os.CLONE_NEWNS)
time.sleep(0.5)
