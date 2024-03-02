#!/usr/bin/env python3
# 本地ip数据包重定向

import socket
import pywind.evtframework.handlers.udp_handler as udp_handler


class local_pfwd(udp_handler.udp_handler):
    # 对端端口
    __peer_port = None

    def init_func(self, creator_fd, local_port: int, peer_port: int):
        self.__peer_port = peer_port

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.set_socket(s)
        self.bind(("127.0.0.1", local_port))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        # 丢弃非允许的端口数据包
        if address[1] != self.__peer_port: return
        self.dispatcher.handle_msg_from_local_pfwd(message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def msg_from_tunnel(self, message):
        self.sendto(message, ("127.0.0.1", self.__peer_port))
        self.add_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
