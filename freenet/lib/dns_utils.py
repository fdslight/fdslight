#!/usr/bin/env python3

import struct, socket

HEADER_FMT = "!HHHHHH"


def is_aaaa_request(dnspkt: bytes):
    xid, flags, questions, answer_rrs, authority_rrs, add_rrs = struct.unpack(HEADER_FMT, dnspkt[0:12])

    # 检查QR值
    if flags & 0x8000 != 0: return False
    # 一般AAAA查询或者A查询都只有一个问题
    if questions != 1: return False

    is_aaaa = False
    dns_fmt_ok = False
    dnspkt = dnspkt[12:]

    while 1:
        try:
            length = dnspkt[0]
        except IndexError:
            break

        offset = length + 1
        dnspkt = dnspkt[offset:]

        if length == 0:
            dns_fmt_ok = True
            break
        ''''''
    if not dns_fmt_ok: return False
    if len(dnspkt) < 4: return False

    _type, = struct.unpack("!H", dnspkt[0:2])

    if _type == 28: is_aaaa = True

    return is_aaaa


def is_a_request(dnspkt: bytes):
    xid, flags, questions, answer_rrs, authority_rrs, add_rrs = struct.unpack(HEADER_FMT, dnspkt[0:12])

    # 检查QR值
    if flags & 0x8000 != 0: return False
    # 一般AAAA查询或者A查询都只有一个问题
    if questions != 1: return False

    is_a = False
    dns_fmt_ok = False
    dnspkt = dnspkt[12:]

    while 1:
        try:
            length = dnspkt[0]
        except IndexError:
            break

        offset = length + 1
        dnspkt = dnspkt[offset:]

        if length == 0:
            dns_fmt_ok = True
            break
        ''''''
    if not dns_fmt_ok: return False
    if len(dnspkt) < 4: return False

    _type, = struct.unpack("!H", dnspkt[0:2])

    if _type == 1: is_a = True

    return is_a


def build_dns_no_such_name_response(xid: int, host: str, is_ipv6=False):
    """构建DNS no such name 响应
    """
    header_data = struct.pack(HEADER_FMT, xid, 0x8183, 0x0001, 0x0000, 0x0000, 0x0000)
    if is_ipv6:
        qtype = 28
    else:
        qtype = 1

    host_list = host.split(".")
    _list = [header_data, ]

    for s in host_list:
        length = len(s)
        _list.append(bytes([length]))
        _list.append(s.encode("iso-8859-1"))
    _list.append(b"\0")
    _list.append(struct.pack("!HH", qtype, 0x0001))

    return b"".join(_list)


def build_dns_addr_response(xid, host, addr, is_ipv6=False):
    """构建DNS A或者AAAA响应
    """
    header_data = struct.pack(HEADER_FMT, xid, 0x8180, 0x0001, 0x0001, 0x0000, 0x0000)
    if is_ipv6:
        qtype = 28
        x = 16
        byte_addr = socket.inet_pton(socket.AF_INET6, addr)
    else:
        qtype = 1
        x = 4
        byte_addr = socket.inet_pton(socket.AF_INET, addr)

    host_list = host.split(".")
    _list = [header_data, ]

    for s in host_list:
        length = len(s)
        _list.append(bytes([length]))
        _list.append(s.encode("iso-8859-1"))
    _list.append(b"\0")
    _list.append(struct.pack("!HH", qtype, 0x0001))
    _list.append(
        struct.pack("!HHHIH", 0xc00c, qtype, 0x0001, 0x0000000f, x)
    )
    _list.append(byte_addr)

    return b"".join(_list)


"""
zz = "7d710100000100000000000003777777036d736e02636e0000010001"
seq = []
b, e = (0, 2,)
while 1:
    s = zz[b:e]
    if not s: break
    s = "0x%s" % s
    n = int(s, 16)
    seq.append(n)
    b = e
    e += 2

dnspkt = bytes(seq)
print(is_aaaa_request(dnspkt))
"""

# print(build_dns_no_such_name_response(0x0011, "www.google.com",is_ipv6=True))
# print(build_dns_addr_response(0x0001,"www.google.com","192.168.2.2"))