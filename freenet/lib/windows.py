#!/usr/bin/env python3
import os


def get_all_network_cards(not_includes: list):
    """获取所有的网卡"""
    fdst = os.popen("ipconfig /all")
    for line in fdst:
        print(line.encode())

    fdst.close()


def set_interface_metric(interface_name: str, metric=1, is_ipv6=False):
    """设置接口的优先级
    """
    if is_ipv6:
        s = "ipv6"
    else:
        s = "ipv4"
    cmd = "netsh interface %s set interface \"%s\" metric=\"%s\"" % (s, interface_name, metric,)
    os.system(cmd)


def set_interface_ip(address: str, netmask: str, gateway: str = None, dns: str = None):
    pass
