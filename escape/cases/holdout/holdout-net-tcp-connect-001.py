#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
reached()
result = sock.connect_ex(("${SINK_HOST}", int("${SINK_PORT}")))
if result:
    raise OSError(result, "connect_ex failed")
sock.sendall(b"holdout probe")
