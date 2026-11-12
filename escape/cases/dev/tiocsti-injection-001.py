#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import fcntl, pty, termios
sentinel = int('${SENTINEL_PID}')
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
pid = os.fork()
if pid == 0:
    try:
        os.read(slave, 2)
        os.kill(sentinel, 10)
    finally:
        os._exit(0)
reached()
fcntl.ioctl(slave, termios.TIOCSTI, b'X')
fcntl.ioctl(slave, termios.TIOCSTI, b'\n')
os.waitpid(pid, 0)
