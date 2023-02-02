#!/usr/bin/env python3
"""客户端隧道实现
"""
import socket, time

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import freenet.lib.logging as logging
import freenet.lib.racs as racs


class udp_tunnel(udp_handler.udp_handler):
    __LOOP_TIMEOUT = 10
    __update_time = 0
    __server_address = None

    __encrypt = None
    __decrypt = None

    __priv_key = None
    __tunnel_ok = None

    __address = None
    __enable = None

    __is_ipv6 = None

    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)

        if is_ipv6:
            self.bind(("::", 0))
        else:
            self.bind(("0.0.0.0", 0))

        self.__encrypt = racs.encrypt(is_tcp=False)
        self.__decrypt = racs.decrypt(is_tcp=False)
        self.__priv_key = None
        self.__tunnel_ok = False
        self.__address = address
        self.__enable = False
        self.__is_ipv6 = is_ipv6

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        return self.fileno

    def create_tunnel(self):
        server_ip = self.dispatcher.get_racs_server_ip(self.__address[0])

        if not server_ip: return False

        self.__server_address = (server_ip, self.__address[1],)
        self.__tunnel_ok = True

    def udp_readable(self, message, address):
        if not self.__tunnel_ok: return
        if not self.__server_address: return
        # 核对地址是否一致
        if self.__server_address[0] != address[0]: return
        if self.__server_address[1] != address[1]: return

        rs = self.__decrypt.unwrap(message)
        if not rs: return
        user_id, msg = rs

        if user_id != self.__priv_key: return
        # 如果消息为空,那么说明为心跳包,丢弃,服务端会回心跳包,如果来回回,那么会造成死循环
        if not msg: return
        self.dispatcher.send_to_local(msg)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        logging.print_general("udp_error", self.__server_address)
        self.delete_handler(self.fileno)

    def send_heartbeat(self):
        self.send_msg(b"")

    def udp_timeout(self):
        t = time.time()
        v = t - self.__update_time

        if not self.__enable:
            self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
            return

        if not self.__tunnel_ok:
            self.create_tunnel()
            self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
            return

        if v > 29:
            self.send_heartbeat()
            self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
            self.__update_time = t
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
        self.dispatcher.tell_racs_close()

    def set_key(self, key: str):
        self.__encrypt.set_key(key)
        self.__decrypt.set_key(key)

    def set_priv_key(self, priv_key: str):
        self.__priv_key = racs.calc_str_md5(priv_key)

    def send_msg(self, message: bytes):
        if not self.__server_address: return
        if not self.__tunnel_ok: return

        wrap_data = self.__encrypt.wrap(self.__priv_key, message)

        self.sendto(wrap_data, self.__server_address)
        self.add_evt_write(self.fileno)


class tcp_tunnel(tcp_handler.tcp_handler):
    __LOOP_TIMEOUT = 10
    __update_time = 0
    __server_address = None

    __encrypt = None
    __decrypt = None

    __priv_key = None
    __tunnel_ok = None

    __address = None
    __is_ipv6 = None

    __header_ok = None

    __crc32 = None
    __payload_len = None

    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)

        self.set_socket(s)

        self.__encrypt = racs.encrypt(is_tcp=True)
        self.__decrypt = racs.decrypt(is_tcp=True)
        self.__priv_key = None
        self.__tunnel_ok = False
        self.__address = address
        self.__is_ipv6 = is_ipv6
        self.__update_time = time.time()
        self.__header_ok = False

        server_ip = self.dispatcher.get_racs_server_ip(self.__address[0])

        if not server_ip:
            logging.print_general("DNS_NOT_FOUND", self.__address)
            s.close()
            return -1

        self.__server_address = (server_ip, self.__address[1],)
        self.connect(self.__server_address)

        return self.fileno

    def connect_ok(self):
        self.__update_time = time.time()
        self.__tunnel_ok = True

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        # 发送心跳包表明自己身份
        self.send_heartbeat()

        logging.print_general("conn_ok", self.__address)

    def send_msg(self, message: bytes):
        if not self.__tunnel_ok: return
        if len(message) > 1500: return

        wrap_data = self.__encrypt.wrap(self.__priv_key, message)

        self.writer.write(wrap_data)
        self.add_evt_write(self.fileno)

    def send_heartbeat(self):
        self.send_msg(b"")

    def tcp_timeout(self):
        if not self.is_conn_ok():
            logging.print_general("conn_fail", self.__address)
            self.delete_handler(self.fileno)
            return

        t = time.time()
        v = t - self.__update_time

        if v > 60:
            logging.print_general("conn_timeout", self.__address)
            self.delete_handler(self.fileno)
            return

        self.send_heartbeat()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_error(self):
        logging.print_general("conn_error", self.__address)
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
        self.dispatcher.tell_racs_close()

    def set_key(self, key: str):
        self.__encrypt.set_key(key)
        self.__decrypt.set_key(key)

    def set_priv_key(self, priv_key: str):
        self.__priv_key = racs.calc_str_md5(priv_key)

    def parse_header(self):
        if self.reader.size() < racs.TCP_HEADER_SIZE:
            return

        self.__crc32, self.__payload_len = self.__decrypt.unwrap_tcp_header(self.reader.read(racs.TCP_HEADER_SIZE))
        self.__header_ok = True

    def tcp_readable(self):
        if not self.__header_ok:
            self.parse_header()
        if not self.__header_ok:
            return

        if self.reader.size() < self.__payload_len: return

        try:
            priv_key, msg = self.__decrypt.unwrap_tcp_body(self.reader.read(self.__payload_len), self.__crc32)
        except racs.TCPPktWrong:
            logging.print_general("WRONG_NETPKT", self.__address)
            self.delete_handler(self.fileno)
            return
        self.__header_ok = False
        if priv_key != self.__priv_key:
            logging.print_general("WRONG_PRIV_KEY", self.__address)
            self.delete_handler(self.fileno)
            return
        self.__update_time = time.time()
        if not msg: return
        self.dispatcher.send_to_local(msg)
        self.tcp_readable()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)
