#!/usr/bin/env python3

"""
协议格式为
user_id:16 bytes
TCP_PAYLOAD_LEN:2 bytes //UDP不需要

"""
import sys, hashlib, struct


class TCPPktWrong(Exception):
    pass


TCP_HEADER_SIZE = 18

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("please install cryptography module")
    sys.exit(-1)


def _encrypt(key, none, aad, byte_data):
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.encrypt(none, byte_data, aad)
    except:
        return None
    return data


def _decrypt(key, none, aad, byte_data):
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(none, byte_data, aad)
    except:
        return None

    return data


def get_size(byte_size):
    return 16 + byte_size


def calc_str_md5(s: str):
    md5 = hashlib.md5()
    md5.update(s.encode())

    return md5.digest()


class crypto_base(object):
    __key = None
    __is_tcp = None
    __user_id = None

    def __init__(self, key: str, is_tcp=False):
        self.__is_tcp = is_tcp
        key = calc_str_md5(key)
        self.__key = key

    @property
    def key(self):
        return self.__key

    @property
    def is_tcp(self):
        return self.__is_tcp

    def set_user_id(self, user_id):
        self.__user_id = user_id

    @property
    def user_id(self):
        return self.__user_id


class encrypt(crypto_base):
    def wrap(self, user_id: bytes, byte_data: bytes):
        size = len(byte_data)
        new_size = get_size(size)

        _list = [
            user_id,
        ]

        if self.is_tcp:
            _list.append(struct.pack("!H", new_size))

        _list.append(_encrypt(self.key, user_id, user_id, byte_data))

        return b"".join(_list)


class decrypt(crypto_base):
    def unwrap_tcp_header(self, tcp_header: bytes):
        user_id = tcp_header[0:16]
        payload_len, = struct.unpack("!H", tcp_header[16:18])
        self.set_user_id(user_id)

        return -1, payload_len

    def unwrap_tcp_body(self, body_data: bytes, *args):
        data = _decrypt(self.key, self.user_id, self.user_id, body_data)
        if data is None: raise TCPPktWrong

        return self.user_id, data

    def unwrap(self, byte_data: bytes):
        if len(byte_data) < 32: return None
        user_id = byte_data[0:16]
        edata = byte_data[16:]

        data = _decrypt(self.key, user_id, user_id, edata)
        if data is None: return None

        return user_id, data
