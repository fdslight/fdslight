#!/usr/bin/env python3

"""基于HTTP的协议如下
session_id由HTTP协商头部提供
version:1 byte 版本,固定为1
action:1 byte 动作
payload_length: 2 bytes 包的总长度
"""
import struct
import pywind.lib.reader as reader

HTTP_FMT = "!BBH"


class encrypt(object):
    """基于HTTP的协议
    """

    def __init__(self, *args, **kwargs):
        pass

    def __build_proto_headr(self, action, payload_len):
        res = struct.pack(
            HTTP_FMT, 1, action, payload_len
        )
        return res

    def build_packet(self, action, byte_data):
        seq = []

        a, b = (0, 60000,)

        while 1:
            _byte_data = byte_data[a:b]
            if not _byte_data: break

            payload_len = len(_byte_data)
            base_hdr = self.__build_proto_headr(action, payload_len)

            seq.append(b"".join([base_hdr, _byte_data]))
            a, b = (b, b + 60000,)

        return b"".join(seq)

    def config(self, *args, **kwargs):
        pass

    def reset(self):
        pass


class decrypt(object):
    __reader = None
    __header_ok = False
    __action = 0
    __results = None
    __payload_length = None

    def __init__(self, *args, **kwargs):
        self.__reader = reader.reader()
        self.__results = []
        self.__payload_length = 0
        self.__action = 0

    def config(self, *args, **kwargs):
        pass

    def can_continue_parse(self):
        size = self.__reader.size()
        if not self.__header_ok and size < 4: return False
        if not self.__header_ok: return True

        return size >= self.__payload_length

    def reset(self):
        self.__payload_length = 0
        self.__header_ok = False

    def get_pkt(self):
        try:
            return self.__results.pop(0)
        except IndexError:
            return None

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        size = self.__reader.size()

        if self.__header_ok:
            if size < self.__payload_length: return
            body = self.__reader.read(self.__payload_length)

            self.__results.append((self.__action, body,))
            self.reset()
            return

        if self.__reader.size() < 4: return

        self.__header_ok = True
        V, action, payload_len = struct.unpack(HTTP_FMT, self.__reader.read(4))
        self.__payload_length = payload_len
        self.__action = action
