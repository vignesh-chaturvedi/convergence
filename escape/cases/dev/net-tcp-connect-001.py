#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
reached()
s.connect(('${SINK_HOST}', int('${SINK_PORT}')))
s.sendall(b'probe')
