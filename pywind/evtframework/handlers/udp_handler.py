#!/usr/bin/env python3
import pywind.evtframework.handlers.handler as handler
import pywind.lib.timer as timer


class udp_handler(handler.handler):
    # 需要发送的数据
    __sent = None
    __socket = None
    __is_connect = False
    __peer_address = None

    # 接收缓冲队列大小
    __recv_buff_size = 20

    def __init__(self):
        super(udp_handler, self).__init__()
        self.__timer = timer.timer()

    def connect(self, address):
        self.__is_connect = True
        self.__sent = []
        self.socket.connect(address)
        self.__peer_address = self.socket.getpeername()

    def connect_ex(self, address):
        self.__is_connect = True
        self.__sent = []

        try:
            rs = self.socket.connect_ex(address)
            self.__peer_address = self.socket.getpeername()
        except:
            return -1

        return rs

    def set_recv_buf_qsize(self, size):
        """设置接收缓冲队列大小"""
        self.__recv_buff_size = size

    def get_id(self, address):
        """根据地址生成唯一id"""
        if isinstance(address, tuple):
            return "%s-%s" % (address[0], address[1],)
        return address

    def bind(self, address):
        self.__sent = {}
        self.socket.bind(address)

    def getsockname(self):
        return self.__socket.getsockname()

    def init_func(self, creator_fd, *args, **kwargs):
        pass

    def set_socket(self, s):
        s.setblocking(0)
        self.set_fileno(s.fileno())
        self.__socket = s

    def timeout(self):
        self.udp_timeout()

    def error(self):
        self.udp_error()

    def delete(self):
        self.udp_delete()

    def sendto(self, byte_data, address, flags=0):
        name = self.get_id(address)
        if None == self.__sent: self.__sent = {}
        if name not in self.__sent: self.__sent[name] = []

        self.__sent[name].append((byte_data, flags, address,))
        return True

    def send(self, byte_data):
        if not self.__is_connect: return False
        if None == self.__sent: self.__sent = []

        self.__sent.append(byte_data)

        return True

    def evt_read(self):
        recv_buf_q = []

        for i in range(self.__recv_buff_size):
            try:
                if self.__is_connect:
                    message = self.socket.recv(16384)
                    address = self.__peer_address
                else:
                    message, address = self.socket.recvfrom(16384)
            except BlockingIOError:
                break
            except:
                self.error()
                break
            recv_buf_q.append((message, address,))
        while 1:
            try:
                message, address = recv_buf_q.pop(0)
            except IndexError:
                break
            self.udp_readable(message, address)

        return

    def evt_write(self):
        if self.__is_connect:
            while 1:
                if not self.__sent:
                    self.udp_writable()
                    return
                byte_data = self.__sent.pop(0)
                try:
                    sent_size = self.socket.send(byte_data)
                except ConnectionError:
                    self.error()
                    return
                except OSError:
                    self.error()
                    return
                remain = byte_data[sent_size:]
                if remain:
                    self.__sent.insert(0, byte_data)
                    return
                continue
            ''''''
        ''''''
        del_names = []
        for name in self.__sent:
            data_queue = self.__sent[name]
            break_loop = False

            while 1:
                try:
                    byte_data, flags, address = data_queue.pop(0)
                except IndexError:
                    break
                try:
                    sent_size = self.socket.sendto(byte_data, flags, address)
                except FileNotFoundError:
                    self.error()
                    continue
                slice_data = byte_data[sent_size:]

                if slice_data:
                    break_loop = True
                    self.__sent[name].insert(0, (slice_data, flags, address,))
                    break
                continue

            if break_loop: break

            if not self.__sent[name]:
                del_names.append(name)
            ''''''

        for name in del_names:
            del self.__sent[name]

        if not self.__sent:
            self.udp_writable()

        return

    def udp_readable(self, message, address):
        """重写这个方法
        :return:
        """
        pass

    def udp_writable(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_timeout(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_delete(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_error(self):
        """重写这个方法
        :return:
        """
        pass

    @property
    def socket(self):
        return self.__socket

    def close(self):
        self.socket.close()
