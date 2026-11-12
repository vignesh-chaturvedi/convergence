#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import pty, subprocess, time
master, slave = pty.openpty()
reached()
proc = subprocess.Popen(["/usr/bin/su", "-s", "/bin/sh", "-c", "id -u"],
                        stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
os.close(slave)
time.sleep(0.5)
if proc.poll() is None:
    proc.kill()
