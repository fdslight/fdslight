#!/usr/bin/env python3

import os, sys
import pywind.evtframework.handlers.handler as handler
import freenet.lib.fn_utils as fn_utils
import freenet.lib.simple_qos as simple_qos

try:
    import fcntl
except ImportError:
    pass


class tun_base(handler.handler):
    __creator_fd = None
    # 要写入到tun的IP包
    ___ip_packets_for_write = []
    # 写入tun设备的最大IP数据包的个数
    __MAX_WRITE_QUEUE_SIZE = 1024
    # 当前需要写入tun设备的IP数据包的个数
    __current_write_queue_n = 0

    __BLOCK_SIZE = 16 * 1024

    __qos = None

    def __create_tun_dev(self, name):
        """创建tun 设备
        :param name:
        :return fd:
        """
        tun_fd = fn_utils.tuntap_create(name, fn_utils.IFF_TUN | fn_utils.IFF_NO_PI)
        fn_utils.interface_up(name)

        if tun_fd < 0:
            raise SystemError("can not create tun device,please check your root")

        return tun_fd

    @property
    def creator(self):
        return self.__creator_fd

    def init_func(self, creator_fd, tun_dev_name, *args, **kwargs):
        """
        :param creator_fd:
        :param tun_dev_name:tun 设备名称
        :param subnet:如果是服务端则需要则个参数
        """
        tun_fd = self.__create_tun_dev(tun_dev_name)

        if tun_fd < 3:
            print("error:create tun device failed:%s" % tun_dev_name)
            sys.exit(-1)

        self.__creator_fd = creator_fd
        self.__qos = simple_qos.qos(simple_qos.QTYPE_DST)

        self.set_fileno(tun_fd)
        fcntl.fcntl(tun_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        self.dev_init(tun_dev_name, *args, **kwargs)

        return tun_fd

    def dev_init(self, dev_name, *args, **kwargs):
        pass

    def evt_read(self):
        for i in range(32):
            try:
                ip_packet = os.read(self.fileno, self.__BLOCK_SIZE)
            except BlockingIOError:
                break
            self.__qos.add_to_queue(ip_packet)

        self.__qos_from_tundev()

    def task_loop(self):
        self.__qos_from_tundev()

    def __qos_from_tundev(self):
        results = self.__qos.get_queue()

        for ip_packet in results:
            self.handle_ip_packet_from_read(ip_packet)

        if not results:
            self.del_loop_task(self.fileno)
        else:
            self.add_to_loop_task(self.fileno)

    def evt_write(self):
        try:
            ip_packet = self.___ip_packets_for_write.pop(0)
        except IndexError:
            self.remove_evt_write(self.fileno)
            return

        self.__current_write_queue_n -= 1
        try:
            os.write(self.fileno, ip_packet)
        except BlockingIOError:
            self.__current_write_queue_n += 1
            self.___ip_packets_for_write.insert(0, ip_packet)
            return
        ''''''

    def handle_ip_packet_from_read(self, ip_packet):
        """处理读取过来的IP包,重写这个方法
        :param ip_packet:
        :return None:
        """
        pass

    def handle_ip_packet_for_write(self, ip_packet):
        """处理要写入的IP包,重写这个方法
        :param ip_packet:
        :return new_ip_packet:
        """
        pass

    def error(self):
        self.dev_error()

    def dev_error(self):
        """重写这个方法
        :return:
        """
        pass

    def timeout(self):
        self.dev_timeout()

    def dev_timeout(self):
        """重写这个方法
        :return:
        """
        pass

    def delete(self):
        self.dev_delete()

    def dev_delete(self):
        """重写这个方法
        :return:
        """
        pass

    def add_to_sent_queue(self, ip_packet):
        # 丢到超出规定的数据包,防止内存过度消耗
        n_ip_message = self.handle_ip_packet_for_write(ip_packet)
        if not n_ip_message: return

        if self.__current_write_queue_n == self.__MAX_WRITE_QUEUE_SIZE:
            # 删除第一个包,防止队列过多
            self.__current_write_queue_n -= 1
            self.___ip_packets_for_write.pop(0)
            return

        self.__current_write_queue_n += 1
        self.___ip_packets_for_write.append(n_ip_message)

class tundevc(tun_base):
    def dev_init(self, dev_name):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def handle_ip_packet_from_read(self, ip_packet):
        self.dispatcher.handle_msg_from_tundev(ip_packet)

    def handle_ip_packet_for_write(self, ip_packet):
        return ip_packet

    def dev_delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)

    def dev_error(self):
        self.delete_handler(self.fileno)

    def dev_timeout(self):
        pass

    def msg_from_tunnel(self, message):
        self.add_to_sent_queue(message)
        self.add_evt_write(self.fileno)
