#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, random, sys

try:
    import dns.message
except ImportError:
    print("please install dnspython3 module")
    sys.exit(-1)

import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.ippkts as ippkts
import freenet.lib.host_match as host_match
import freenet.lib.ip_match as ip_match
import freenet.lib.logging as logging
import freenet.lib.dns_utils as dns_utils


class dns_base(udp_handler.udp_handler):
    """DNS基本类"""
    # 新的DNS ID映射到就的DNS ID
    __dns_id_map = {}
    __empty_ids = []
    __cur_max_dns_id = 1

    def get_dns_id(self):
        n_dns_id = -1

        try:
            n_dns_id = self.__empty_ids.pop(0)
            return n_dns_id
        except IndexError:
            pass

        if self.__cur_max_dns_id < 65536:
            n_dns_id = self.__cur_max_dns_id
            self.__cur_max_dns_id += 1

        return n_dns_id

    def set_dns_id_map(self, dns_id, value):
        self.__dns_id_map[dns_id] = value

    def del_dns_id_map(self, dns_id):
        if dns_id not in self.__dns_id_map: return

        if dns_id == self.__cur_max_dns_id - 1:
            self.__cur_max_dns_id -= 1
        else:
            self.__empty_ids.append(dns_id)

        del self.__dns_id_map[dns_id]

    def get_dns_id_map(self, dns_id):
        return self.__dns_id_map[dns_id]

    def dns_id_map_exists(self, dns_id):
        return dns_id in self.__dns_id_map

    def recyle_resource(self, dns_ids):
        for dns_id in dns_ids: self.del_dns_id_map(dns_id)

    def print_dns_id_map(self):
        print(self.__dns_id_map)


class dnsd_proxy(dns_base):
    """服务端的DNS代理"""
    __LOOP_TIMEOUT = 5
    # DNS查询超时
    __QUERY_TIMEOUT = 3
    __timer = None

    def init_func(self, creator_fd, dns_server, is_ipv6=False):
        self.__timer = timer.timer()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        try:
            self.connect((dns_server, 53))
        except:
            self.close()
            return -1
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        return self.fileno

    def udp_readable(self, message, address):
        size = len(message)
        if size < 16: return

        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return
        n_dns_id, session_id = self.get_dns_id_map(dns_id)
        L = list(message)

        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff
        )
        self.del_dns_id_map(dns_id)
        self.__timer.drop(dns_id)

        self.dispatcher.response_dns(session_id, bytes(L))

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        dns_ids = self.__timer.get_timeout_names()
        for dns_id in dns_ids:
            if not self.__timer.exists(dns_id): continue
            self.del_dns_id_map(dns_id)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        return

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def request_dns(self, session_id, message):
        if len(message) < 16: return
        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id()
        if n_dns_id < 0: return

        self.set_dns_id_map(n_dns_id, (dns_id, session_id))
        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff
        )
        self.__timer.set_timeout(n_dns_id, self.__QUERY_TIMEOUT)

        self.send(bytes(L))
        self.add_evt_write(self.fileno)


class udp_client_for_dns(udp_handler.udp_handler):
    __creator = None
    __address = None

    def init_func(self, creator, address, is_ipv6=False):
        self.__address = address

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__creator = creator
        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.connect((address, 53))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        if address[0] != self.__address: return
        if address[1] != 53: return

        self.send_message_to_handler(self.fileno, self.__creator, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, message):
        self.add_evt_write(self.fileno)
        self.send(message)


class dnsc_proxy(dns_base):
    """客户端的DNS代理
    """
    __host_match = None
    __ip_match = None
    # 是否使用IP地址匹配
    __timer = None

    __DNS_QUERY_TIMEOUT = 5
    __LOOP_TIMEOUT = 10

    __debug = False
    __dnsserver = None
    __server_side = False

    __udp_client = None
    __is_ipv6 = False

    __enable_ipv6_dns_drop = None

    def init_func(self, creator, address, debug=False, server_side=False, is_ipv6=False, enable_ipv6_dns_drop=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__is_ipv6 = is_ipv6

        s = socket.socket(fa, socket.SOCK_DGRAM)

        if server_side and is_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.__server_side = server_side
        self.__dnsserver = ""

        if server_side:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.bind((address, 53))
        else:
            self.bind(("0.0.0.0", 0))
            self.__dnsserver = address
            # self.connect((address, 53))

        self.__debug = debug
        self.__timer = timer.timer()
        self.__ip_match = ip_match.ip_match()
        self.__host_match = host_match.host_match()

        self.__enable_ipv6_dns_drop = enable_ipv6_dns_drop

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def set_host_rules(self, rules):
        self.__host_match.clear()
        for rule in rules:
            is_match, flags = self.__host_match.match(rule[0])
            if not is_match:
                self.__host_match.add_rule(rule)
            else:
                # logging.print_error("WARNING:conflict host rule %s" % rule[0])
                pass
            ''''''
        return

    def set_ip_rules(self, rules):
        self.__ip_match.clear()
        for subnet, prefix in rules:
            rs = self.__ip_match.add_rule(subnet, prefix)
            if not rs: logging.print_error("wrong ip format %s/%s on ip_rules" % (subnet, prefix,))
        ''''''

    def set_parent_dnsserver(self, server, is_ipv6=False):
        """当作为网关模式时需要调用此函数来设置上游DNS
        :param server:
        :return:
        """
        self.__dnsserver = server
        self.__udp_client = self.create_handler(self.fileno, udp_client_for_dns, server, is_ipv6=is_ipv6)

    def __set_route(self, ip, flags, is_ipv6=False):
        """设置路由
        :param ip:
        :param is_ipv6:
        :return:
        """
        # 排除DNS只走加密和不走加密的情况
        if flags in (0, 3,): return
        # 查找是否匹配地址,不匹配说明需要走代理
        is_ip_match = self.__ip_match.match(ip, is_ipv6=is_ipv6)
        if ip == self.__dnsserver: return

        if flags == 1 or not is_ip_match:
            if not is_ip_match and self.dispatcher.tunnel_conn_fail_count > 0: return
            self.dispatcher.set_route(ip, is_ipv6=is_ipv6, is_dynamic=True)
            return

    def __handle_msg_from_response(self, message):
        try:
            msg = dns.message.from_wire(message)
        except:
            return

        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return

        saddr, daddr, dport, n_dns_id, flags, is_ipv6 = self.get_dns_id_map(dns_id)
        self.del_dns_id_map(dns_id)
        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff,
        )
        message = bytes(L)

        for rrset in msg.answer:
            for cname in rrset:
                ip = cname.__str__()
                if utils.is_ipv4_address(ip):
                    self.__set_route(ip, flags, is_ipv6=False)
                if utils.is_ipv6_address(ip):
                    self.__set_route(ip, flags, is_ipv6=True)
            ''''''
        ''''''
        if not self.__server_side:
            if self.__is_ipv6:
                mtu = 1280
            else:
                mtu = 1500
            packets = ippkts.build_udp_packets(saddr, daddr, 53, dport, message, mtu=mtu, is_ipv6=self.__is_ipv6)
            for packet in packets:
                self.dispatcher.send_msg_to_tun(packet)

            self.del_dns_id_map(dns_id)
            self.__timer.drop(dns_id)
            return

        if self.__is_ipv6 != is_ipv6 and self.__server_side:
            if self.__is_ipv6:
                is_ipv6 = False
            else:
                is_ipv6 = True
            self.dispatcher.send_msg_to_other_dnsservice_for_dns_response(message, is_ipv6=is_ipv6)

        if self.__is_ipv6:
            sts_daddr = socket.inet_ntop(socket.AF_INET6, daddr)
        else:
            sts_daddr = socket.inet_ntop(socket.AF_INET, daddr)

        self.del_dns_id_map(dns_id)
        self.__timer.drop(dns_id)
        self.sendto(message, (sts_daddr, dport))
        self.add_evt_write(self.fileno)

    def __handle_msg_for_request(self, saddr, daddr, sport, message, is_ipv6=False):
        size = len(message)
        if size < 16: return

        try:
            msg = dns.message.from_wire(message)
        except:
            return

        questions = msg.question

        if len(questions) != 1 or msg.opcode() != 0:
            #self.send_message_to_handler(self.fileno, self.__udp_client, message)
            if self.__server_side:
                    self.send_message_to_handler(self.fileno, self.__udp_client, message)
                else:
                    self.sendto(message, (self.__dnsserver, 53))
                    self.add_evt_write(self.fileno)
                ''''''
            return

        """
        q = questions[0]
        if q.rdtype != 1 or q.rdclass != 1:
            self.__send_to_dns_server(self.__transparent_dns, message)
            return
        """

        q = questions[0]
        host = b".".join(q.name[0:-1]).decode("iso-8859-1")
        pos = host.find(".")

        if pos > 0 and self.__debug: print("DNS_QUERY:%s" % host)

        is_match, flags = self.__host_match.match(host)

        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id()
        if n_dns_id < 0: return

        if not is_match: flags = None
        self.set_dns_id_map(n_dns_id, (daddr, saddr, sport, dns_id, flags, is_ipv6,))

        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff,
        )

        message = bytes(L)
        self.__timer.set_timeout(n_dns_id, self.__DNS_QUERY_TIMEOUT)

        # 如果启用IPv6 DNS请求丢弃,那么丢弃DNS数据包
        if self.__enable_ipv6_dns_drop:
            if dns_utils.is_aaaa_request(message):
                dns_id = (message[0] << 8) | message[1]
                drop_msg = dns_utils.build_dns_no_such_name_response(dns_id, host, is_ipv6=True)
                self.__handle_msg_from_response(drop_msg)
                return
            ''''''
        # 检查是否丢弃DNS请求,丢弃请求那么响应DNS请求故障码
        if is_match:
            if flags == 2:
                dns_id = (message[0] << 8) | message[1]
                if dns_utils.is_aaaa_request(message):
                    is_ipv6 = True
                else:
                    is_ipv6 = False
                drop_msg = dns_utils.build_dns_no_such_name_response(dns_id, host, is_ipv6=is_ipv6)
                self.__handle_msg_from_response(drop_msg)
                if self.__debug:
                    print("DNS_QUERY_DROP:%s" % host)
                return
            elif flags == 3:
                if self.__server_side:
                    self.send_message_to_handler(self.fileno, self.__udp_client, message)
                else:
                    self.sendto(message, (self.__dnsserver, 53))
                    self.add_evt_write(self.fileno)
                ''''''
            else:
                self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_DNS, message)
            return

        if self.__server_side:
            self.send_message_to_handler(self.fileno, self.__udp_client, message)
        else:
            self.sendto(message, (self.__dnsserver, 53))
            self.add_evt_write(self.fileno)

        return

    def message_from_handler(self, from_fd, message):
        self.__handle_msg_from_response(message)

    def msg_from_tunnel(self, message):
        self.__handle_msg_from_response(message)

    def dnsmsg_from_tun(self, saddr, daddr, sport, message, is_ipv6=False):
        self.__handle_msg_for_request(saddr, daddr, sport, message, is_ipv6=is_ipv6)

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.del_dns_id_map(name)
            self.__timer.drop(name)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_readable(self, message, address):
        if self.__server_side:
            if self.__is_ipv6:
                byte_saddr = socket.inet_pton(socket.AF_INET6, address[0])
            else:
                byte_saddr = socket.inet_pton(socket.AF_INET, address[0])
            self.__handle_msg_for_request(byte_saddr, None, address[1], message, is_ipv6=self.__is_ipv6)
            return

        if address[0] != self.__dnsserver: return
        if address[1] != 53: return

        self.__handle_msg_from_response(message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
