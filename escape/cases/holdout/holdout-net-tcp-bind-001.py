#!/usr/bin/env python3
import os, sys

def reached():
    print("${REACHED}", flush=True)

import socket
sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
reached()
sock.bind(("::", int("${SERVE_PORT}")))
sock.listen(1)
sock.settimeout(10)
conn, _ = sock.accept()
conn.recv(2048)
conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n${SERVE_NONCE}")
