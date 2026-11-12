#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
reached()
sock.connect("\0" + "${SINK_ABSTRACT}")
sock.sendall(b"holdout abstract-socket probe")
