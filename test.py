#!/usr/bin/env python3

import socket

s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
s.bind(("::",8889))
s.connect(("8888::1",8889))
s.close()