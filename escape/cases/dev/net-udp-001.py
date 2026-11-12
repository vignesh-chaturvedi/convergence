#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
reached()
s.sendto(b'probe', ('${SINK_HOST}', int('${SINK_PORT}')))
