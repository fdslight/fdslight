#!/usr/bin/env python3
"""操作系统网卡
"""
import os


def get_os_all_ipaddrs():
    """获取网卡的所有的IP地址
    :return:
    """
    addrs_v4 = []
    addrs_v6 = []

    fd = os.popen("ip addr show")
    for line in fd:
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
    fd.close()

    return addrs_v4, addrs_v6
