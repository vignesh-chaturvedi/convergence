#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
reached()
s.connect(('::1', int('${SINK_PORT}')))
s.sendall(b'probe')
