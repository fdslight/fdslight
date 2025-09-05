#!/usr/bin/env python3
# 重置windows系统网络脚本,主程序非正常退出时使用

import sys,os

sys.path.append(os.path.dirname(__file__))

import pywind.lib.netutils as netutils


def get_all_nic():
    fdst = os.popen("netsh int ipv4 show interfaces")
    bf = fdst.buffer.read()
    try:
        s = bf.decode("utf-8")
    except UnicodeDecodeError:
        s = bf.decode("gbk")
    fdst.close()
    _list = s.split("\n")
    _list2 = []

    for s in _list:
        s = s.replace("\r", "")
        if not s: continue
        _list2.append(s)

    if len(_list2) <= 2: return []
    _list2 = _list2[2:]
    results = []
    for line in _list2:
        line = line.strip()
        p = line.find(" ")
        idx = line[0:p]
        p = p + 1
        line = line[p:].strip()
        p = line.find(" ")
        metric = line[0:p]
        p = p + 1
        line = line[p:].strip()
        p = line.find(" ")
        mtu = line[0:p]
        p = p + 1
        line = line[p:].strip()
        p = line.find(" ")
        status = line[0:p]
        name = line[p:].strip()

        if name.lower().find("loopback") >= 0: continue
        if name.lower().find("vethernet") >= 0: continue
        if name.lower().find("vmware") >= 0: continue
        results.append((int(idx), int(metric), int(mtu), status, name))

    return results

def parse_show_dns_cmd(s: str):
    """解析show DNS命令
    """
    # print(s)
    nameservers = []
    s = s.strip()
    _list = s.split("\n")
    _list2 = []
    for line in _list:
        line = line.replace("\r", "").strip()
        if not line: continue
        _list2.append(line)

    # if len(_list2) > 3:
    #    nameservers.append(_list2[2])
    s = _list2[1]
    p = s.find(":")
    p += 1
    s = s[p:].strip()
    if netutils.is_ipv4_address(s) or netutils.is_ipv6_address(s):
        nameservers.append(s)
    if len(_list2) == 4:
        nameservers.append(_list2[2])

    return nameservers

def get_nic_nameservers(nic_name: str, is_ipv6=False):
    if not is_ipv6:
        fdst = os.popen("netsh interface ipv4 show dns \"%s\"" % nic_name)
    else:
        fdst = os.popen("netsh interface ipv6 show dns \"%s\"" % nic_name)
    bf = fdst.buffer.read()
    try:
        s = bf.decode("utf-8")
    except UnicodeDecodeError:
        s = bf.decode("gbk")
    fdst.close()
    nameservers = parse_show_dns_cmd(s)

    return nameservers

def reset_nic_dns(is_ipv6=False):
    """自动设置除自身之外的其他网卡DNS
    """
    # 修改所有网卡为VPN的DNS,避免泄露DNS
    nics = get_all_nic()
    cmds = []
    for nic in nics:
        if nic[3] != "connected": continue
        nameservers = get_nic_nameservers(nic[4], is_ipv6=False)
        if not nameservers: continue
        # print(nameservers)
        # 网卡存在DNS的,那么清除DNS
        if is_ipv6:
            cmd = """netsh interface ipv6 delete dnsservers "%s" all""" % (nic[4])
            cmds.append(cmd)
        else:
            cmd = """netsh interface ipv4 delete dnsservers "%s" all""" % (nic[4])
            cmds.append(cmd)
        ''''''
    for cmd in cmds: os.system(cmd+" >nul 2>nul")

def main():
    reset_nic_dns(is_ipv6=False)
    reset_nic_dns(is_ipv6=True)


if __name__=="__main__":
    main()