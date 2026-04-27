#!/usr/bin/env python3
"""操作系统网卡
"""
import os, subprocess


def get_os_all_ipaddrs():
    """获取网卡的所有的IP地址
    :return:
    """
    addrs_v4 = []
    addrs_v6 = []

    p = subprocess.run("ip addr show", capture_output=True, shell=True)
    _list = p.stdout.decode().split("\n")

    for line in _list:
        is_ipv6 = False

        line = line.strip()
        line = line.replace("\r", "")
        line = line.replace("\n", "")
        if not line: continue

        p1 = line.find("inet")
        p2 = line.find("inet6")

        if p1 < 0 and p2 < 0: continue
        if p2 >= 0: is_ipv6 = True

        _list = line.split(" ")
        s = _list[1]
        p = s.find("/")
        if p < 1: continue

        addr = s[0:p]

        if is_ipv6:
            addrs_v6.append(addr)
        else:
            addrs_v4.append(addr)
        ''''''

    return addrs_v4, addrs_v6
