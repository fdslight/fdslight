#!/usr/bin/env python3

import socket, random, hashlib


def ip4b_2_number(ip_pkt):
    """ipv4 bytes转换为数字"""
    return (ip_pkt[0] << 24) | (ip_pkt[1] << 16) | (ip_pkt[2] << 8) | ip_pkt[3]


def ip4s_2_number(string):
    """ipv4 字符串转换为数字"""
    ip_pkt = socket.inet_aton(string)
    return ip4b_2_number(ip_pkt)


def rand_string(length):
    """生成随机KEY"""
    sts = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    size = len(sts)
    tmplist = []
    for i in range(length):
        n = random.randint(0, size - 1)
        tmplist.append(
            sts[n]
        )

    return "".join(tmplist)


def calc_content_md5(content):
    md5 = hashlib.md5()
    md5.update(content)

    return md5.digest()


def calc_net_prefix_num(prefix, is_ipv6=False):
    """根据前缀计算网络掩码"""
    if is_ipv6:
        m = 128
        n = 2 ** 128 - 1
    else:
        m = 32
        n = 2 ** 32 - 1

    r = 0
    t = m - prefix

    while t > 0:
        t = t - 1
        r |= 1 << t

    return (~r) & n


def get_byte_net_mask(prefix, is_ipv6=False):
    """通过prefix获取byte形式的掩码
    :param prefix:
    :param is_ipv6:
    :return:
    """
    a = int(prefix / 8)
    b = prefix % 8
    seq = []

    pad_num = 0

    if b == 0:
        if is_ipv6:
            pad_num = 16 - a
        else:
            pad_num = 4 - a
    else:
        if is_ipv6:
            pad_num = 15 - a
        else:
            pad_num = 3 - a

    for i in range(a): seq.append(0xff)

    if b != 0:
        x = 0
        for i in range(b):
            x |= 1 << (7 - i)
        seq.append(x)

    for i in range(pad_num):
        seq.append(0x00)

    return bytes(seq)


def ip_addr_plus(byte_ip):
    """把IP地址加1
    :param byte_ip:
    :param is_ipv6:
    :return:
    """
    seq = list(byte_ip)
    seq.reverse()
    size = len(seq)

    carry = False
    for i in range(size):
        n = seq[i]
        if i == 0 or carry:
            n = n + 1
            if n > 0xff:
                carry = True
                n = 0
                seq[i] = n
                continue
            carry = False
            seq[i] = n
            break
        ''''''
    seq.reverse()
    return bytes(seq)


def ip_addr_minus(byte_ip):
    """对IP地址减1
    :param byte_ip:
    :return:
    """
    seq = list(byte_ip)
    size = len(seq)
    seq.reverse()

    flags = False
    for i in range(size):
        n = seq[i]
        if i == 0 or flags:
            if 0 == n:
                n = 0xff
                flags = True
                seq[i] = n
                continue
            flags = False
            seq[i] = n - 1
            break
        ''''''
    seq.reverse()
    return bytes(seq)


def get_ip_addr_max(subnet, prefix, is_ipv6=False):
    """获取当前子网的最大IP地址
    :param subnet:
    :param prefix:
    :param is_ipv6:
    :return:
    """
    if is_ipv6:
        fa = socket.AF_INET6
        size = 16
    else:
        fa = socket.AF_INET
        size = 4

    byte_subnet = socket.inet_pton(fa, subnet)
    byte_mask = get_byte_net_mask(prefix, is_ipv6=is_ipv6)

    seq_a = list(byte_subnet)
    seq_b = list(byte_mask)
    results = []

    for i in range(size):
        n = seq_a[i] | ((~seq_b[i]) & 0xff)
        results.append(n)

    return socket.inet_ntop(fa, bytes(results))


def calc_subnet(ipaddr, prefix, is_ipv6=False):
    if is_ipv6 and prefix == 128: return ipaddr
    if not is_ipv6 and prefix == 32: return ipaddr

    q = int(prefix / 8)
    r = prefix % 8

    if is_ipv6:
        byte_ipaddr = socket.inet_pton(socket.AF_INET6, ipaddr)
        results = list(bytes(16))
    else:
        byte_ipaddr = socket.inet_pton(socket.AF_INET, ipaddr)
        results = list(bytes(4))

    results[0:q] = byte_ipaddr[0:q]
    v = 0
    for n in range(r + 1):
        if n == 0: continue
        v += 2 ** (8 - n)
    results[q] = byte_ipaddr[q] & v
    if is_ipv6:
        return socket.inet_ntop(socket.AF_INET6, bytes(results))
    else:
        return socket.inet_ntop(socket.AF_INET, bytes(results))


def check_subnet_fmt(subnet, prefix, is_ipv6=False):
    """检查子网格式是否正确"""
    if is_ipv6 and not is_ipv6_address(subnet): return False
    if not is_ipv6 and not is_ipv4_address(subnet): return False

    try:
        prefix = int(prefix)
    except ValueError:
        return False
    if not is_ipv6 and prefix > 32: return False
    if prefix < 0: return False
    if is_ipv6 and prefix > 128: return False

    if is_ipv6:
        fa = socket.AF_INET6
    else:
        fa = socket.AF_INET

    byte_subnet = socket.inet_pton(fa, subnet)

    n_subnet = calc_subnet(subnet, prefix, is_ipv6)

    byte_n_subnet = socket.inet_pton(fa, n_subnet)
    # 通过二进制比较,因为IPv6地址可简写
    return byte_n_subnet == byte_subnet


def check_is_from_subnet(ipaddr, subnet, prefix, is_ipv6=False):
    """检查IP地址是否来自于子网"""
    n_subnet = calc_subnet(ipaddr, prefix, is_ipv6)

    if is_ipv6:
        fa = socket.AF_INET6
    else:
        fa = socket.AF_INET

    # 通过二进制比较,因为IPv6地址可简写
    byte_subnet = socket.inet_pton(fa, subnet)
    byte_n_subnet = socket.inet_pton(fa, n_subnet)

    return byte_subnet == byte_n_subnet


def number2bytes(n, fixed_size=0):
    seq = []

    while n != 0:
        t = n & 0xff
        seq.insert(0, t)
        n = n >> 8

    if fixed_size:
        size = len(seq)
        for i in range(fixed_size - size): seq.insert(0, 0)

    return bytes(seq)


def bytes2number(byte_data):
    v = 0
    for n in byte_data: v = (v << 8) | n
    return v


def is_ipv4_address(sts_ipaddr):
    """检查是否是IPv4地址"""
    if not isinstance(sts_ipaddr, str): return False
    if len(sts_ipaddr) < 7: return False

    seq = sts_ipaddr.split(".")
    if len(seq) != 4: return False

    for c in seq:
        try:
            v = int(c)
            if v > 255: return False
        except ValueError:
            return False
        ''''''
    try:
        socket.inet_aton(sts_ipaddr)
    except OSError:
        return False
    return True


def is_ipv6_address(sts_ipaddr):
    """检查是否是IPv6地址"""
    if not isinstance(sts_ipaddr, str): return False
    if sts_ipaddr.find(":") < 0: return False
    seq = sts_ipaddr.split(":")

    for s in seq:
        if not s: continue
        s = "0x%s" % s
        try:
            int(s, 16)
        except ValueError:
            return False

    try:
        socket.inet_pton(socket.AF_INET6, sts_ipaddr)
    except OSError:
        return False
    return True


def extract_subnet_info(sts):
    """从字符串中提取子网信息，字符串的格式为 xxxx／prefix
    :param sts:
    :return:成功返回 （subnet,prefix,) ,否则返回 None
    """
    pos = sts.find("/")

    if pos < 2: return None
    subnet = sts[0:pos]
    pos += 1

    try:
        prefix = int(sts[pos:])
    except ValueError:
        return None

    return (subnet, prefix,)


def is_uint(s):
    """是否是无符号整数
    :param s:
    :return:
    """
    try:
        n = int(s)
    except ValueError:
        return False

    return n >= 0


MBUF_AREA_SIZE = 1501


class mbuf(object):
    __list = None

    __payload_size = 0
    offset = 0

    def __init__(self):
        self.__list = list(bytes(MBUF_AREA_SIZE))

    def get_data(self):
        return bytes(self.__list[self.offset:self.__payload_size])

    def get_part(self, size):
        if size == 1: return self.__list[self.offset]

        end = self.offset + size

        return bytes(self.__list[self.offset:end])

    def copy2buf(self, byte_data):
        size = len(byte_data)
        if size > MBUF_AREA_SIZE: return False

        n = 0
        for i in byte_data:
            self.__list[n] = i
            n += 1

        self.__payload_size = size
        return True

    def ip_version(self):
        return (self.__list[0] & 0xf0) >> 4

    @property
    def payload_size(self):
        return self.__payload_size

    def replace(self, byte_data):
        size = len(byte_data)
        if size > self.__payload_size - self.offset: raise ValueError

        i = self.offset
        for n in byte_data:
            self.__list[i] = n
            i += 1
        return True

# print(check_subnet_fmt("F000:0000:0000:0000:0000:0000:0000:0000", 2, is_ipv6=True))
