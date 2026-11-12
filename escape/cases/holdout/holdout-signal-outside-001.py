#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import signal
pid = int("${SENTINEL_PID}")
pidfd = os.pidfd_open(pid, 0)
reached()
signal.pidfd_send_signal(pidfd, signal.SIGUSR1)
os.close(pidfd)
