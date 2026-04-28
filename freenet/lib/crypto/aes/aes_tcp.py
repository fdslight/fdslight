#!/usr/bin/env python3
"""TCP版本的AES加密模块"""
"""
import sys
sys.path.append("../../../")
"""

import hashlib
import os

import freenet.lib.base_proto.tunnel_tcp as tunnel
import freenet.lib.crypto.aes._aes_gcm as aes_gcm
import freenet.lib.base_proto.utils as proto_utils


class encrypt(tunnel.builder):
    __key = b""
    __xv = b""

    def __init__(self):
        super(encrypt, self).__init__(16 + tunnel.MIN_FIXED_HEADER_SIZE)

    def wrap_header(self, base_hdr):
        xv = os.urandom(16)
        self.__xv = xv

        return self.__xv + base_hdr

    def wrap_body(self, size, body_data):
        return aes_gcm.encrypt(self.__key, self.__xv, self.__xv, body_data)

    def get_payload_length(self, pkt_len):
        return aes_gcm.get_size(pkt_len)

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
import ixc_proxy.lib.base_proto.utils as proto_utils

key = "name"
builder = encrypt()
builder.config({"key": key})

e_rs = builder.build_packet(bytes(16), proto_utils.ACT_IPDATA, b"hello")
e_rs = list(e_rs)
e_rs[0] = 100
e_rs = bytes(e_rs)
builder.reset()

parser = decrypt()
parser.config({"key": "name"})
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())

e_rs = builder.build_packet(bytes(16), proto_utils.ACT_IPDATA, b"world")
builder.reset()
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())
"""
