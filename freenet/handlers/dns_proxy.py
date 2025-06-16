#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.lib.timer as timer

import socket, sys, struct, ssl, time, platform

try:
    import dns.message
except ImportError:
    print("please install dnspython3 module")
    sys.exit(-1)

import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils

if platform.system().lower() != "windows":
    import freenet.lib.ippkts as ippkts
else:
    import freenet.lib.win_ippkts as ippkts

import freenet.lib.host_match as host_match
import freenet.lib.ip_match as ip_match
import freenet.lib.logging as logging
import freenet.lib.dns_utils as dns_utils
import freenet.lib.ssl_backports as ssl_backports


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
    __is_ipv6 = False

    __enable_ipv6_dns_drop = None

    def init_func(self, creator, address, debug=False, is_ipv6=False, enable_ipv6_dns_drop=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__is_ipv6 = is_ipv6

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.__dnsserver = ""

        if is_ipv6:
            self.bind(("::", 0))
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

    @property
    def hosts(self):
        return self.dispatcher.hosts

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

    def resp_dns_packet(self, saddr, daddr, sport, dport, message, mtu, is_ipv6=False):
        packets = ippkts.build_udp_packets(saddr, daddr, sport, dport, message, mtu=mtu, is_ipv6=is_ipv6)
        for packet in packets:
            self.dispatcher.send_msg_to_tun(packet)
        return

    def handle_msg_from_response(self, message):
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
        if self.__is_ipv6:
            mtu = 1280
        else:
            mtu = 1500
        self.resp_dns_packet(saddr, daddr, 53, dport, message, mtu, is_ipv6=self.__is_ipv6)
        self.del_dns_id_map(dns_id)
        self.__timer.drop(dns_id)

    def __handle_msg_for_request(self, saddr, daddr, sport, message, is_ipv6=False):
        # 检查DoT是否启用,开启DoT并且DoT失连,那么重新打开DoT
        if self.dispatcher.enable_dot:
            if self.dispatcher.dot_fd < 0:
                self.dispatcher.dot_open()
            ''''''
        size = len(message)
        if size < 16: return

        dns_id = (message[0] << 8) | message[1]

        try:
            msg = dns.message.from_wire(message)
        except:
            return

        questions = msg.question

        if len(questions) != 1 or msg.opcode() != 0:
            # self.send_message_to_handler(self.fileno, self.__udp_client, message)
            # 如果开启DoT并且DoT连不上那么使用传统DNS查询
            if self.dispatcher.enable_dot and self.dispatcher.dot_fd >= 0:
                self.get_handler(self.dispatcher.dot_fd).send_to_server(message)
            else:
                self.sendto(message, (self.__dnsserver, 53))
                self.add_evt_write(self.fileno)
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

        if self.__is_ipv6:
            mtu = 1280
        else:
            mtu = 1500

        a_hosts = self.hosts["A"]
        aaaa_hosts = self.hosts['AAAA']
        ip6_addr = aaaa_hosts.get(host, "")
        ip4_addr = a_hosts.get(host, "")
        hosts_resp_flags = False

        if dns_utils.is_aaaa_request(message):
            if ip6_addr:
                hosts_resp_flags = True
                resp_msg = dns_utils.build_dns_addr_response(dns_id, host, ip6_addr, is_ipv6=True)
            else:
                # 如果该地址在IPv4 hosts存在,IPv6不存在,那么AAAA请求返回IPv6不存在
                if ip4_addr:
                    hosts_resp_flags = True
                    resp_msg = dns_utils.build_dns_no_such_name_response(dns_id, host, is_ipv6=True)
                ''''''
            ''''''
        if dns_utils.is_a_request(message):
            ip4_addr = a_hosts.get(host, "")
            if ip4_addr:
                hosts_resp_flags = True
                resp_msg = dns_utils.build_dns_addr_response(dns_id, host, ip4_addr, is_ipv6=False)
            else:
                # 如果该地址在IPv6 hosts存在,IPv6不存在,那么A请求返回IPv4不存在
                if ip6_addr:
                    hosts_resp_flags = True
                    resp_msg = dns_utils.build_dns_no_such_name_response(dns_id, host, is_ipv6=False)
                ''''''
            ''''''

        if hosts_resp_flags:
            self.resp_dns_packet(daddr, saddr, 53, sport, resp_msg, mtu, is_ipv6=self.__is_ipv6)
            return

        is_match, flags = self.__host_match.match(host)

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
                self.handle_msg_from_response(drop_msg)
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
                self.handle_msg_from_response(drop_msg)
                if self.__debug:
                    print("DNS_QUERY_DROP:%s" % host)
                return
            elif flags == 3:
                # 如果开启DoT并且DoT连不上那么使用传统DNS查询
                if self.dispatcher.enable_dot and self.dispatcher.dot_fd >= 0:
                    self.get_handler(self.dispatcher.dot_fd).send_to_server(message)
                else:
                    self.sendto(message, (self.__dnsserver, 53))
                    self.add_evt_write(self.fileno)
                ''''''
            else:
                self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_DNS, message)
            return
        # 如果开启DoT并且DoT连不上那么使用传统DNS查询
        if self.dispatcher.enable_dot and self.dispatcher.dot_fd >= 0:
            self.get_handler(self.dispatcher.dot_fd).send_to_server(message)
        else:
            self.sendto(message, (self.__dnsserver, 53))
            self.add_evt_write(self.fileno)
        return

    def message_from_handler(self, from_fd, message):
        self.handle_msg_from_response(message)

    def msg_from_tunnel(self, message):
        self.handle_msg_from_response(message)

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
        if address[0] != self.__dnsserver: return
        if address[1] != 53: return

        self.handle_msg_from_response(message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()


class dot_client(tcp_handler.tcp_handler):
    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0
    __ssl_handshake_ok = None
    __hostname = ""

    __tmp_buf = None

    __header_ok = None
    __length = 0

    __host = None
    __debug = None

    def init_func(self, creator, host, hostname, port=853, conn_timeout=30, is_ipv6=False, debug=False):
        self.__host = host
        self.__ssl_handshake_ok = False
        self.__hostname = hostname
        self.__update_time = time.time()
        self.__conn_timeout = conn_timeout
        self.__tmp_buf = []
        self.__header_ok = False
        self.__length = 0
        self.__debug = debug

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        s = context.wrap_socket(s, do_handshake_on_connect=False, server_hostname=self.__hostname)

        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.dispatcher.ca_path)

        self.set_socket(s)
        self.__conn_timeout = conn_timeout

        server_ip = self.dispatcher.get_server_ip(host)
        if server_ip is None:
            logging.print_error("cannot get %s ip address" % host)
            s.close()
            return -1

        self.connect((server_ip, port))

        return self.fileno

    def connect_ok(self):
        if self.__debug:
            print("DoT:connect DoT server %s OK" % self.__host)
        self.__update_time = time.time()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.add_evt_write(self.fileno)

    def evt_read(self):
        if not self.is_conn_ok():
            super().evt_read()
            return

        if not self.__ssl_handshake_ok:
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return

        try:
            super().evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLWantReadError:
            if self.reader.size() > 0:
                self.tcp_readable()
        except ssl.SSLZeroReturnError:
            if self.reader.size() > 0:
                self.tcp_readable()
            if self.handler_exists(self.fileno): self.delete_handler(self.fileno)
        except ssl.SSLError:
            self.delete_handler(self.fileno)
        except:
            logging.print_error()
            self.delete_handler(self.fileno)

    def evt_write(self):
        if not self.is_conn_ok():
            super().evt_write()
            return

        if not self.__ssl_handshake_ok:
            self.remove_evt_write(self.fileno)
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return
        try:
            super().evt_write()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLEOFError:
            self.delete_handler(self.fileno)
        except ssl.SSLError:
            self.delete_handler(self.fileno)
        except:
            logging.print_error()
            self.delete_handler(self.fileno)

    def check_cert_is_expired(self):
        peer_cert = self.socket.getpeercert()
        expire_time = peer_cert["notAfter"]
        t = time.strptime(expire_time, "%b %d %H:%M:%S %Y %Z")
        expire_secs = time.mktime(t)
        now = time.time()

        if now > expire_secs: return True

        return False

    def flush_sent_buf(self):
        while 1:
            try:
                data = self.__tmp_buf.pop(0)
            except IndexError:
                break
            self.writer.write(data)
        self.add_evt_write(self.fileno)

    def do_ssl_handshake(self):
        try:
            self.socket.do_handshake()
            self.__ssl_handshake_ok = True
            cert = self.socket.getpeercert()
            if not hasattr(ssl, 'match_hostname'):
                ssl_backports.match_hostname(cert, self.__hostname)
            else:
                ssl.match_hostname(cert, self.__hostname)
            if self.check_cert_is_expired():
                logging.print_error("SSL handshake fail %s;certificate is expired" % self.__host)
                self.delete_handler(self.fileno)
                return
            self.add_evt_read(self.fileno)
            # 清空发送缓冲,发送数据
            self.flush_sent_buf()
            if self.__debug:
                print("DoT:SSL handshake OK %s" % self.__host)
            ''''''
        except ssl.SSLWantReadError:
            self.add_evt_read(self.fileno)
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLZeroReturnError:
            self.delete_handler(self.fileno)
            # logging.print_error("SSL handshake fail %s" % self.__hostname)
        except:
            logging.print_error("SSL ERROR %s" % self.__host)
            self.delete_handler(self.fileno)
        ''''''

    def parse_header(self):
        if self.reader.size() < 2: return
        self.__length, = struct.unpack("!H", self.reader.read(2))
        self.__header_ok = True

    def tcp_readable(self):
        self.__update_time = time.time()
        is_err = False
        while 1:
            if not self.__header_ok:
                self.parse_header()
            if not self.__header_ok: break
            if self.__length > 1500:
                is_err = True
                break
            if self.__length > self.reader.size(): break

            message = self.reader.read(self.__length)

            if len(message) >= 8:
                self.get_handler(self.dispatcher.dns_fd).handle_msg_from_response(message)
            self.__header_ok = False

        if is_err: self.delete_handler(self.fileno)

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        if self.__debug:
            if not self.is_conn_ok():
                print("DoT:cannot connect to host %s" % self.__host)
            print("DoT:delete DoT connect object from host %s" % self.__host)
        self.dispatcher.tell_dot_close()
        self.__tmp_buf = []
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        if self.__debug:
            print("DoT:tcp error from host %s" % self.__host)
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        now = time.time()
        if now - self.__update_time >= self.__conn_timeout:
            if self.__debug: print("DoT:timeout from host %s" % self.__host)
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def send_to_server(self, message: bytes):
        length = len(message)
        # 限制数据包大小
        if length > 1400: return
        if length < 8: return

        wrap_msg = struct.pack("!H", length) + message

        if not self.__ssl_handshake_ok:
            self.__tmp_buf.append(wrap_msg)
            return
        self.add_evt_write(self.fileno)
        self.writer.write(wrap_msg)
        self.send_now()
