#!/usr/bin/env python3
"""
协议格式为
TCP_CRC32: TCP header,4 bytes
TCP_PAYLOAD_LEN:2 bytes
UDP OR TCP PUBLIC BODY
pad_length:1byte //加密的填充长度
user_id:16 bytes //用户key
"""
import sys, hashlib, struct, zlib

TCP_HEADER_SIZE = 6

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("please install cryptography module")
    sys.exit(-1)


def _encrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(byte_data) + encryptor.finalize()


def _decrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(byte_data) + decryptor.finalize()


def get_size(byte_size):
    n = int(byte_size / 16)
    r = byte_size % 16

    if r != 0: n += 1

    return n * 16


def calc_str_md5(s: str):
    md5 = hashlib.md5()
    md5.update(s.encode())

    return md5.digest()


class TCPPktWrong(Exception):
    pass


class crypto_base(object):
    __key = None
    __is_tcp = None

    def __init__(self, is_tcp=False):
        self.__is_tcp = is_tcp
        self.__key = None

    @property
    def key(self):
        return self.__key

    @property
    def is_tcp(self):
        return self.__is_tcp

    def set_key(self, key: str):
        key = calc_str_md5(key)
        self.__key = key

class encrypt(crypto_base):
    def __get_tcp_wrap(self, _list: list):
        byte_data = b"".join(_list)
        size = len(byte_data)

        header = struct.pack("!IH", zlib.crc32(byte_data), size)

        return b"".join([header, byte_data])

    def wrap(self, user_id: bytes, byte_data: bytes):
        size = len(byte_data)
        new_size = get_size(size)
        x = new_size - size

        _list = [
            struct.pack("!B16s", x, user_id),
            _encrypt(self.key, user_id, b"".join([byte_data, b"\0" * x]))
        ]

        if self.is_tcp:
            return self.__get_tcp_wrap(_list)
        else:
            return b"".join(_list)


class decrypt(crypto_base):
    def unwrap_tcp_header(self, tcp_header: bytes):
        if len(tcp_header) < 6: return
        crc32, payload_len = struct.unpack("!IH", tcp_header)

        return crc32, payload_len

    def unwrap_tcp_body(self, body_data: bytes, check_crc32: int):
        crc32 = zlib.crc32(body_data)
        if check_crc32 != crc32:
            raise TCPPktWrong

        return self.unwrap(body_data)

    def unwrap(self, byte_data: bytes):
        if len(byte_data) < 17: return None

        pad_size = byte_data[0]
        user_id = byte_data[1:17]

        rs = _decrypt(self.key, user_id, byte_data[17:])
        size = len(rs) - pad_size

        return user_id, rs[0:size]


"""
import os
a = encrypt("hello", is_tcp=True)
b = decrypt("hello", is_tcp = True)
rs = a.wrap(os.urandom(16), b"hello,world,zzzzzzzzzzzzzzzzzzzzzzzzz")
crc32,payload_len=b.unwrap_tcp_header(rs[0:6])
print(b.unwrap_tcp_body(rs[6:],crc32))
"""