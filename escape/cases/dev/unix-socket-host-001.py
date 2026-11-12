#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
reached()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('${SINK_PATH}')
s.sendall(b'probe')
