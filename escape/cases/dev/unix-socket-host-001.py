#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
reached()
s.connect('${SINK_PATH}')
s.sendall(b'probe')
