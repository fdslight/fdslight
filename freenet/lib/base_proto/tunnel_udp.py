#!/usr/bin/env python3
"""协议帧格式
session_id: 16bytes 会话ID,为MD5值
timestamp:8 bytes 时间截
tot_len:2 bytes 未分包前的数据长度
payload_length:2 bytes 实际负载数据长度
tot_seg: 4 bit 全部的分包个数
seq: 4 bit 当前分包序号
reverse:4 bit 保留
action:4bit 动作
"""
import freenet.lib.base_proto.utils as proto_utils
import struct, time

MIN_FIXED_HEADER_SIZE = 30

_FMT = "!16sQHHbb"


class builder(object):
    __session_id = 0
    __fixed_header_size = 0
    # 数据块大小
    __block_size = 1150
    __max_pkt_size = 0

    def __init__(self, fixed_header_size, pkt_size=1232):
        if fixed_header_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "the header size can not less than %s" % MIN_FIXED_HEADER_SIZE)

        self.__block_size = pkt_size - fixed_header_size
        self.__fixed_header_size = fixed_header_size
        self.__max_pkt_size = self.__block_size * 2

    def set_session_id(self, session_id):
        self.__session_id = session_id

    @property
    def block_size(self):
        return self.__block_size

    def __gen_raib(self, block_a, block_b):
        """生成冗余数据块,类似于磁盘阵列的RAID5模式,较少丢包率
        """
        size_a = len(block_a)
        size_b = len(block_b)

        list_a = list(block_a)
        list_b = list(block_b)

        L = None
        if size_a > size_b:
            L = list_b
        else:
            L = list_a
        n = abs(size_a - size_b)
        for i in range(n): L.append(0)
        csum_list = []
        cnt = 0
        for n in list_a:
            csum = n ^ list_b[cnt]
            cnt += 1
            csum_list.append(csum)

        return (bytes(list_a), bytes(list_b), bytes(csum_list),)

    def __build_proto_header(self, session_id, pkt_len, real_size, tot_seg, seq, action):
        if action not in proto_utils.ACTS: raise ValueError("not support action type")
        return struct.pack(
            _FMT, session_id, int(time.time()),
            pkt_len, real_size, (tot_seg << 4) | seq, action
        )

    def __get_sent_raw_data(self, data_len, byte_data, redundancy=False):
        """获取要发送的原始数据"""
        if data_len == 0: return [b"", ]

        # 不开启数据冗余那么直接返回
        if not redundancy: return [byte_data, ]

        data_block_size = self.__block_size - self.__fixed_header_size
        tmplist = []
        b, e = (0, data_block_size,)

        while b < data_len:
            t = byte_data[b:e]
            b = e
            e += data_block_size
            tmplist.append(t)

        # 如果有2个数据块,那么启用数据冗余,减少丢包率
        if len(tmplist) == 2:
            a, b = tuple(tmplist)
            ret_v = self.__gen_raib(a, b)
        else:
            # 只有一个数据块那么就不启用数据冗余
            ret_v = tuple(tmplist)
        return ret_v

    def build_packets(self, session_id, action, byte_data, redundancy=False):
        """
        :param session_id: 
        :param action: 
        :param byte_data: 
        :param redundancy:是否开启UDP数据冗余
        :return: 
        """
        if len(session_id) != 16: raise proto_utils.ProtoError("the size of session_id must be 16")

        data_len = len(byte_data)

        if data_len > self.__max_pkt_size:
            raise proto_utils.ProtoError("the size of byte data muse be less than %s" % self.__max_pkt_size + 1)

        data_seq = []
        tmp_t = self.__get_sent_raw_data(data_len, byte_data, redundancy=redundancy)
        tot_seq = len(tmp_t)
        seq = 1

        for block in tmp_t:
            size = len(block)
            base_header = self.__build_proto_header(session_id, data_len, size, tot_seq, seq, action)
            e_hdr = self.wrap_header(base_header)
            e_body = self.wrap_body(size, block)
            data_seq.append(b"".join((e_hdr, e_body,)))
            seq += 1

        return data_seq

    def set_max_pkt_size(self, size):
        """单个UDP数据包所能传输的数据大小"""
        min_size = 1000 + self.__fixed_header_size
        if size < min_size: raise proto_utils.ProtoError("the value of size must not be less than %s" % min_size)
        self.__block_size = size

    def wrap_header(self, base_hdr):
        """重写这个方法"""
        return base_hdr

    def wrap_body(self, size, body_data):
        """重写这个方法"""
        return body_data

    @property
    def fixed_header_size(self):
        return self.__fixed_header_size

    def reset(self):
        """
        重写这个方法
        """
        pass

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass


class parser(object):
    __fixed_header_size = 0
    __data_area = None
    # 总共的段数
    __tot_seg = 0

    __pkt_len = 0
    __packet_timeout = 0

    def __init__(self, fixed_header_size):
        if fixed_header_size < MIN_FIXED_HEADER_SIZE: raise proto_utils.ProtoError(
            "the header size can not less than %s" % MIN_FIXED_HEADER_SIZE)

        self.__fixed_header_size = fixed_header_size
        self.__wait_fill_seq = []
        self.__data_area = {}
        # 超过时间的数据包丢弃
        self.__packet_timeout = 5

    def __parse_raib(self, data_block, csum_block):
        """从数据块和校检块中获取另一数据块内容"""
        cnt = 0
        tmp_list = []
        for n in data_block:
            tmp_list.append(n ^ csum_block[cnt])
            cnt += 1

        return bytes(tmp_list)

    def __parse_header(self, header):
        res = struct.unpack(_FMT, header)

        return (
            res[0], res[1], res[2],
            res[3],
            (res[4] & 0xf0) >> 4,
            res[4] & 0x0f, res[5],
        )

    def __get_pkt(self, pkt):
        if len(pkt) < self.__pkt_len: raise proto_utils.ProtoError("wrong packet length")

        return pkt[0:self.__pkt_len]

    def parse(self, packet):
        if len(packet) < self.__fixed_header_size: return
        real_header = self.unwrap_header(packet[0:self.__fixed_header_size])
        if not real_header: return

        session_id, timestamp, pkt_len, payload_len, tot_seg, seq, action = self.__parse_header(real_header)
        real_body = self.unwrap_body(payload_len, packet[self.__fixed_header_size:])

        self.__pkt_len = pkt_len

        # 丢弃超时数据包,这里需要考虑小于0的情况,即时间回退
        now = time.time()
        if now - timestamp < 0 or now - timestamp > self.__packet_timeout: return None
        # 0为非法序号
        if seq == 0: return None
        if seq > 3: return None
        # 如果只有一个数据包,那么直接返回
        if tot_seg == 1:
            self.reset()
            return (session_id, action, real_body,)

        # 最大分段只能是3段
        if tot_seg > 3: return None
        self.__data_area[seq] = real_body

        if 1 in self.__data_area and 2 in self.__data_area:
            pkt = b"".join((self.__data_area[1], self.__data_area[2],))
            self.reset()
            body_data = self.__get_pkt(pkt)
            return (session_id, action, body_data,)
        if len(self.__data_area) == 2:
            result = self.__get_data_from_raib()
            body_data = self.__get_pkt(result)
            self.reset()
            return (session_id, action, body_data,)

        return None

    def __get_data_from_raib(self):
        data_a = None
        n = 0

        if 1 in self.__data_area:
            data_a = self.__data_area[1]
            n = 1

        if 2 in self.__data_area:
            data_a = self.__data_area[2]
            n = 2

        len_a = len(data_a)
        data_b = self.__data_area[3]
        len_b = len(data_b)

        if len_a != len_b:
            self.reset()
            return b""

        data_c = self.__parse_raib(data_a, data_b)
        iter_obj = None
        if n == 1: iter_obj = (data_a, data_c,)
        if n == 2: iter_obj = (data_c, data_a,)

        return b"".join(iter_obj)

    def unwrap_header(self, header_data):
        """
        解包头, 重写这个方法
        """
        return header_data

    def unwrap_body(self, real_size, body_data):
        """
        重写这个方法
        """
        return body_data

    def reset(self):
        """
        重写这个方法,该reset无需手动调用
        """
        self.__tot_seg = 0
        self.__data_area = {}

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass


"""
p = parser(MIN_FIXED_HEADER_SIZE)
b = builder(MIN_FIXED_HEADER_SIZE)

data = list(bytes(1400))
data.append(69)

edata = b.build_packets(bytes(16), 1, b"hello,world")
print(edata)
# edata.pop(1)
# print(edata)

for t in edata:
    rs = p.parse(t)
    if rs: print(rs)
"""
