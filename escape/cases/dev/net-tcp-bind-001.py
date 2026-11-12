#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
reached()
s.bind(('127.0.0.1', int('${SERVE_PORT}')))
s.listen(1)
s.settimeout(10)
c, _ = s.accept()
c.recv(1024)
c.sendall(b'HTTP/1.0 200 OK\r\n\r\n${SERVE_NONCE}')
