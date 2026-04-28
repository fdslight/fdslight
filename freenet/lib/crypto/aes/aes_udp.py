#!/usr/bin/env python3
"""UDP版本的AES加密模块"""

"""
import sys
sys.path.append("../../../")
"""

import os, hashlib

import freenet.lib.base_proto.tunnel_udp as tunnel
import freenet.lib.crypto.aes._aes_gcm as aes_gcm
import freenet.lib.base_proto.utils as proto_utils


class encrypt(tunnel.builder):
    __key = b""
    __xv = b""

    __real_size = 0
    __body_size = 0

    def __init__(self):
        super(encrypt, self).__init__(16 + tunnel.MIN_FIXED_HEADER_SIZE)
        self.set_max_pkt_size(self.block_size - self.block_size % 16)

    def wrap_header(self, base_hdr):
        xv = os.urandom(16)
        self.__xv = xv

        return self.__xv + base_hdr

    def wrap_body(self, size, body_data):
        return aes_gcm.encrypt(self.__key, self.__xv, self.__xv, body_data)

    def __set_aes_key(self, new_key):
        self.__key = hashlib.md5(new_key.encode()).digest()

    def reset(self):
        super(encrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])


class decrypt(tunnel.parser):
    __key = b""
    __xv = b""

    def __init__(self):
        super(decrypt, self).__init__(16 + tunnel.MIN_FIXED_HEADER_SIZE)

    def unwrap_header(self, header_data):
        self.__xv = header_data[0:16]

        return header_data[16:]

    def unwrap_body(self, length, body_data):
        d = aes_gcm.decrypt(self.__key, self.__xv, self.__xv, body_data)
        if d is None: raise proto_utils.ProtoError("decrypt failed")

        return d[0:length]

    def __set_aes_key(self, key):
        new_key = hashlib.md5(key.encode()).digest()
        self.__key = new_key

    def reset(self):
        super(decrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])


"""
length = 1500
L = []

for n in range(length):
    L.append(33)

key = "hello"
builder = encrypt()
builder.config({"key": key})

data=os.urandom(1500)
print(data)
packets = builder.build_packets(bytes(16), 2, data)

parser = decrypt()
parser.config({"key": "hello"})

for pkt in packets:
    ret = parser.parse(pkt)
    if ret: print(ret)
"""
