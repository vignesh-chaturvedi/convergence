#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import socket
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
reached()
sock.sendmsg([b"holdout datagram"], [], 0,
             ("${SINK_HOST}", int("${SINK_PORT}")))
