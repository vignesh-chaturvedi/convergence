#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket, struct
port = int('${SINK_PORT}')
packet = struct.pack('!HHHH', 40000, port, 8 + 5, 0) + b'probe'
reached()
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.sendto(packet, ('${SINK_HOST}', port))
