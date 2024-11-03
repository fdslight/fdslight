#!/usr/bin/env python3
"""计算校检和for windows
"""
import freenet.lib.utils as utils
import random


def __calc_udp_csum(saddr, daddr, udp_data, is_ipv6=False):
    size = len(udp_data)
    seq = [
        saddr, daddr, b'\x00\x11',
        utils.number2bytes(size, 2),
        udp_data,
    ]

    if is_ipv6:
        size += 24
    else:
        size += 12

    if 0 != size % 2:
        seq.append(b"\0")
        size += 1

    data = b"".join(seq)
    # csum = socket.htons(fn_utils.calc_csum(data, size))

    csum = __calc_checksum(data, size)
    # import socket
    # print(csum,socket.htons(csum_t))

    if csum == 0: return 0xffff

    return csum


def __calc_incre_csum(csum, old_field, new_field):
    csum = csum - (~old_field & 0xffff) - new_field
    csum = (csum >> 16) + csum & 0xffff
    csum += (csum >> 16)

    return csum & 0xffff


def __get_ip4_hdrlen(mbuf):
    mbuf.offset = 0
    n = mbuf.get_part(1)
    hdrlen = (n & 0x0f) * 4

    return hdrlen


def __get_protocol(mbuf):
    ip_ver = mbuf.ip_version()
    if ip_ver == 4:
        mbuf.offset = 9
        p = mbuf.get_part(1)
    else:
        mbuf.offset = 6
        p = mbuf.get_part(1)

    return p


def modify_port(port, mbuf, flags=0):
    """修改TCP/SCTP/UDP/UDPLite端口
    :param port:
    :param mbuf:
    :param flags: 0表示修改源端口,1表示修改目的端口
    :return:
    """
    protocols = (6, 17, 132, 136,)
    ip_ver = mbuf.ip_version()
    p = __get_protocol(mbuf)

    if p not in protocols:
        raise ValueError("unsupport IP protocol for modify port")

    if ip_ver == 4:
        hdrlen = __get_ip4_hdrlen(mbuf)
    else:
        hdrlen = 40

    if flags == 0:
        port_off = hdrlen
    else:
        port_off = hdrlen + 2

    mbuf.offset = port_off
    # SCTP特别处理
    if p == 132:
        mbuf.replace(utils.number2bytes(port, 2))
        return

    old_port = utils.bytes2number(mbuf.get_part(2))

    if p in (6, 136,):
        csum_offset = hdrlen + 6
    else:
        csum_offset = hdrlen + 16

    mbuf.offset = csum_offset
    csum = utils.bytes2number(mbuf.get_part(2))

    mbuf.offset = port_off
    mbuf.replace(utils.number2bytes(port, 2))

    # 如果旧的校检和为0,说明不需要进行校检和计算
    if csum == 0: return

    mbuf.offset = csum_offset
    csum = __calc_incre_csum(csum, old_port, port)
    mbuf.replace(utils.number2bytes(csum, 2))


def modify_ip4address(ip_packet, mbuf, flags=0):
    """
    :param ip_packet:
    :param mbuf:
    :param flags: 0表示修改源地址,1表示修改目的地址
    :return:
    """

    mbuf.offset = 9
    protocol = mbuf.get_part(1)

    if flags == 0:
        mbuf.offset = 12
    else:
        mbuf.offset = 16
    old_ip_packet = mbuf.get_part(4)
    mbuf.offset = 10
    csum = utils.bytes2number(mbuf.get_part(2))
    csum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, csum)
    mbuf.replace(utils.number2bytes(csum, 2))

    mbuf.offset = 6
    offset = utils.bytes2number(mbuf.get_part(2)) & 0x1fff
    # 修改第一个数据包
    if protocol in (6, 17, 132, 136,) and offset == 0:
        if protocol == 6:
            p = 1
        else:
            p = 0
        modify_tcpudp_for_change(ip_packet, mbuf, p, flags=flags)

    mbuf.offset = 10

    if flags == 0:
        mbuf.offset = 12
    else:
        mbuf.offset = 16
    mbuf.replace(ip_packet)


def modify_ip6address(ip_packet, mbuf, flags=0):
    """
    :param ip_packet:
    :param ushort_number:新分配的number,如果是分包,那么这个值任意
    :param mbuf:
    :param flags: 0表示修改源地址和端口,1表示修改目的地址和端口
    :return:
    """
    mbuf.offset = 6
    nexthdr = mbuf.get_part(1)

    if nexthdr == 58:
        modify_icmp6_echo_for_change(ip_packet, mbuf, flags=flags)

    if nexthdr in (6, 17, 136,):
        if nexthdr == 6:
            p = 1
        else:
            p = 0
        modify_tcpudp_for_change(ip_packet, mbuf, p, flags=flags)

    if flags == 0:
        mbuf.offset = 8
    else:
        mbuf.offset = 24

    mbuf.replace(ip_packet)


def calc_checksum_for_ip_change(old_ip_packet, new_ip_packet, old_checksum, is_ipv6=False):
    """ ip地址改变之后重新获取校检码
    :param old_ip_packet:
    :param new_ip_packet:
    :param old_checksum:
    :param is_ipv6:是否是ipv6
    :return:
    """
    final_checksum = old_checksum
    a = 0
    b = 1
    # tmpcsum = old_checksum

    if is_ipv6:
        n = 8
    else:
        n = 2

    i = 0
    while i < n:
        old_field = (old_ip_packet[a] << 8) | old_ip_packet[b]
        new_field = (new_ip_packet[a] << 8) | new_ip_packet[b]
        # final_checksum = checksum.calc_incre_checksum(final_checksum, old_field, new_field)
        final_checksum = __calc_incre_csum(final_checksum, old_field, new_field)
        a = a + 2
        b = b + 2
        i += 1

    return final_checksum


def modify_tcpudp_for_change(ip_packet, mbuf, proto, flags=0, is_ipv6=False):
    """ 修改传输层(SCTP,TCP,UDP,UDPLite,)内容
    :param ip_packet:
    :param ip_packet_list:
    :param proto: 0表示计算的UDP以及UDPLITE,1表示计算的TCP
    :param flags: 0 表示修改时的源地址,1表示修改的是目的地址
    :param is_ipv6:表示是否是否是IPV6
    :return:
    """
    if proto not in [0, 1]: return

    if is_ipv6:
        hdr_len = 40
    else:
        mbuf.offset = 0
        hdr_len = (mbuf.get_part(1) & 0x0f) * 4

    if flags:
        if is_ipv6:
            mbuf.offset = 24
        else:
            mbuf.offset = 16
        ''''''
    else:
        if is_ipv6:
            mbuf.offset = 8
        else:
            mbuf.offset = 12
        ''''''
    if is_ipv6:
        old_ip_packet = mbuf.get_part(16)
    else:
        old_ip_packet = mbuf.get_part(4)

    if proto == 0:
        n = hdr_len + 6
    else:
        n = hdr_len + 16

    mbuf.offset = n
    csum = utils.bytes2number(mbuf.get_part(2))
    # 如果旧的校检和为0,说明不需要进行校检和计算
    if csum == 0: return

    csum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, csum, is_ipv6=is_ipv6)
    mbuf.replace(utils.number2bytes(csum, 2))


def _calc_incre_checksum(old_checksum, old_field, new_field):
    """使用增量式计算校检和
    :param old_checksum: 2 bytes的旧校检和
    :param old_field: 2 bytes的旧的需要修改字段
    :param new_field: 2 bytes的新的字段
    :return:
        """
    chksum = (~old_checksum & 0xffff) + (~old_field & 0xffff) + new_field
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += (chksum >> 16)

    return (~chksum) & 0xffff


def __calc_checksum(pacekt, size):
    """计算校检和
    :param pacekt:
    :param size:
    :return:
    """
    checksum = 0
    a = 0
    b = 1
    while size > 1:
        checksum += (pacekt[a] << 8) | pacekt[b]
        size -= 2
        a += 2
        b += 2

    if size:
        checksum += pacekt[a]

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    return (~checksum) & 0xffff


def modify_icmp6_echo_for_change(byte_ip, mbuf, flags=0):
    """修改ICMPv6报文
    :param byte_ip:
    :param new_icmpid:
    :param flags:0表示修改请求报文,1表示表示修改响应报文
    :return:
    """
    mbuf.offset = 42
    csum = utils.bytes2number(mbuf.get_part(2))

    if flags == 0:
        mbuf.offset = 8
    else:
        mbuf.offset = 24

    old_byte_ip = mbuf.get_part(16)

    csum = calc_checksum_for_ip_change(old_byte_ip, byte_ip, csum, is_ipv6=True)

    mbuf.offset = 42
    mbuf.replace(utils.number2bytes(csum, 2))


def build_ip_packet(pkt_len, protocol, saddr, daddr, message, pkt_id=1, flags_df=0, flags_mf=0, offset=0):
    """创建IP数据包
    :param pkt_len:包长度
    :param saddr: bytes类型的源地址
    :param daddr: bytes类型的目的地址
    :param message:消息内容
    :param pkt_id: 包ID
    :param flags_df: 分段df位
    :param flags_mf:分段mf位
    :param offset:包偏移
    :return ip_pkt:
    """
    if pkt_len < 20: raise ValueError("the value of pkt_len must be less than 20")
    if protocol < 0 or protocol > 255: raise ValueError("the value of protocol is wrong")

    tpl = b'E\x00\x00\x14\x00\x01\x00\x00@\x00z\xea\x00\x00\x00\x00\x00\x00\x00\x00'

    L = list(tpl)

    # 修改地址
    csum = (L[10] << 8) | L[11]
    csum = calc_checksum_for_ip_change(tpl[12:16], saddr, csum)
    csum = calc_checksum_for_ip_change(tpl[16:20], daddr, csum)
    L[12:16] = saddr
    L[16:20] = daddr

    # 修改包长度
    old_v = (L[2] << 8) | L[3]
    new_v = pkt_len
    csum = __calc_incre_csum(csum, old_v, new_v)
    L[2:4] = ((pkt_len & 0xff00) >> 8, pkt_len & 0x00ff,)

    # 修改包ID
    old_v = (L[4] << 8) | L[5]
    new_v = pkt_id
    csum = __calc_incre_csum(csum, old_v, new_v)
    L[4:6] = ((pkt_id & 0xff00) >> 8, pkt_id & 0x00ff,)

    # 修改flags以及offset
    old_v = (L[6] << 8) | L[7]
    new_v = (flags_df << 14) | (flags_mf << 13) | offset
    csum = __calc_incre_csum(csum, old_v, new_v)
    L[6:8] = ((new_v & 0xff00) >> 8, new_v & 0x00ff,)

    # 修改协议
    old_v = L[9]
    new_v = protocol
    csum = __calc_incre_csum(csum, old_v, new_v)
    L[9] = protocol

    # 修改校检和
    # L[10:12] = (0, 0,)
    # csum = fn_utils.calc_csum(bytes(L), 20)
    L[10:12] = ((csum & 0xff00) >> 8, csum & 0x00ff,)

    return b"".join((bytes(L), message,))


def build_udp_packets(saddr, daddr, sport, dport, message, mtu=1500, is_udplite=False, is_ipv6=False):
    """构建UDP数据包"""
    if mtu > 1500 or mtu < 576: raise ValueError("the value of mtu is wrong!")
    msg_len = 8 + len(message)
    # 构建UDP数据头
    udp_hdr = [
        (sport & 0xff00) >> 8,
        sport & 0x00ff,
        (dport & 0xff00) >> 8,
        dport & 0x00ff,
    ]

    if is_udplite:
        udp_hdr += [
            0, 8,
            0, 0,
        ]
        csum = __calc_checksum(bytes(udp_hdr), 8)
        udp_hdr[6] = (csum & 0xff00) >> 8
        udp_hdr[7] = csum & 0xff
    else:
        udp_hdr += [
            (msg_len & 0xff00) >> 8,
            msg_len & 0x00ff,
            0, 0,
        ]

    if not is_udplite:
        csum = __calc_udp_csum(saddr, daddr,
                               b"".join([bytes(udp_hdr), message]),
                               is_ipv6=is_ipv6)
        udp_hdr[6] = (csum & 0xff00) >> 8
        udp_hdr[7] = csum & 0xff

    pkt_data = b"".join(
        (bytes(udp_hdr), message,)
    )

    if not is_ipv6:
        pkt_id = random.randint(1, 65535)
    else:
        pkt_id = random.randint(1, 0xffffffff)
        flow_label = random.randint(1, 0x0fffff)

    pkts = []
    flags_df = 1

    if is_udplite:
        p = 136
    else:
        p = 17

    if is_ipv6 and mtu - 40 >= msg_len:
        ipv6hdr = __build_ipv6_hdr(flow_label, msg_len, p, 128, saddr, daddr)
        ip6data = b"".join([ipv6hdr, message, ])

        return [ip6data, ]

    if is_ipv6:
        # IPV6分包在扩展头提供,因此要算成48
        ip_hdr_size = 48
    else:
        ip_hdr_size = 20

    step = mtu - ip_hdr_size - (mtu - ip_hdr_size) % 8

    b = 0
    e = step

    # pkt_id = 1
    n = 0
    every_offset = int(step / 8)

    while 1:
        bdata = pkt_data[b:e]
        slice_size = len(bdata)

        if e >= msg_len:
            finish = True
        else:
            finish = False

        if finish:
            flags_mf = 0
        else:
            flags_mf = 1

        offset = n * every_offset

        if not is_ipv6:
            ippkt = build_ip_packet(slice_size + 20, p,
                                    saddr, daddr, bdata, pkt_id=pkt_id,
                                    flags_df=flags_df, flags_mf=flags_mf,
                                    offset=offset
                                    )
        else:
            ipv6hdr = __build_ipv6_hdr(flow_label, slice_size, 44, 128, saddr, daddr)
            frag_hdr = __build_ipv6_fragment_hdr(p, offset, flags_mf, pkt_id)
            ippkt = b"".join([ipv6hdr, frag_hdr, bdata, ])

        pkts.append(ippkt)
        if finish: break
        n += 1
        b = e
        e = b + step

    return pkts


def __build_ipv6_hdr(flow_label, payload_length, nexthdr, hop_limit, saddr, daddr):
    """构建IPV6通用头
    :param flow_label: 
    :param payload_length: 
    :param nexthdr: 
    :param hop_limit: 
    :param saddr: 
    :param daddr: 
    :return: 
    """
    # flow_label = random.randint(1, 0x0fffff)
    byte_seq = [
        utils.number2bytes(6 << 4, 1),
        utils.number2bytes(flow_label & 0x0fffff, 3),
        utils.number2bytes(payload_length, 2),
        utils.number2bytes(nexthdr, 1),
        utils.number2bytes(hop_limit, 1),
        saddr, daddr
    ]

    return b"".join(byte_seq)


def __build_ipv6_fragment_hdr(nexthdr, frag_off, m_flag, frag_id):
    frag_off = (frag_off << 3) | m_flag
    byte_seq = [
        utils.number2bytes(nexthdr, 1),
        b"\0", utils.number2bytes(frag_off, 2),
        utils.number2bytes(frag_id, 4),
    ]

    return b"".join(byte_seq)


"""
import os

data = os.urandom(1600)
pkts = build_udp_packets(b"\0\0\0\1", b"\0\0\0\1", 9999, 9999, data, mtu=1450)

addr = b"\0\0\0\1"
length = 1400

seq = [
    pkts[0][20:],
    pkts[1][20:],
]

data2 = b"".join(seq)

print(__calc_udp_csum(addr, addr, data2))
    """
