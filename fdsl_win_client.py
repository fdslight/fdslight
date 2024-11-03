#!/usr/bin/env python3
# fdslight client for windows
import os, importlib, socket, sys, time, json, zlib, platform, ctypes, winreg

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.timer as timer
import pywind.lib.configfile as configfile
import pywind.lib.netutils as netutils
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.handlers.dns_proxy as dns_proxy
import freenet.handlers.tunnelc as tunnelc
import freenet.lib.file_parser as file_parser
import freenet.lib.logging as logging
import freenet.handlers.racs as racs
import freenet.lib.base_proto.tunnel_over_http as tunnel_over_http
import freenet.lib.wintun_wrapper as wintun_wrapper
import freenet.lib.win_ippkts as ippkts
import dns.resolver


class fdslight_client(dispatcher.dispatcher):
    # 路由超时时间
    __ROUTE_TIMEOUT = 1200
    __conf_dir = None
    __routes = None

    __route_timer = None

    __devname = "fdslight"

    __configs = None

    __mbuf = None

    __dns_fileno = -1
    __dot_fileno = -1
    __enable_dot = False
    __dot_auth_host = None
    __dot_host = None

    __dns_listen6 = -1
    __session_id = None

    __debug = False

    __tcp_crypto = None
    __udp_crypto = None
    __crypto_configs = None

    __support_ip4_protocols = (1, 6, 17, 132, 136,)
    __support_ip6_protocols = (6, 17, 58, 132, 136,)

    # 是否开启IPV6流量
    __enable_ipv6_traffic = False

    # 服务器地址
    __server_ip = None

    # 静态路由,即在程序运行期间一直存在
    __static_routes = None

    # 隧道尝试连接失败次数
    __tunnel_conn_fail_count = None
    __tunnel_fileno = None

    __local_ip = None
    __local_ip6 = None
    __local_ip_prefix = None
    __local_ip6_prefix = None
    __byte_local_ip = None
    __byte_local_ip6 = None
    __local_dns = None
    __local_dns6 = None

    __racs_fd = None
    __racs_cfg = None
    __racs_route_subnet = None
    __racs_route_prefix = None
    __racs_route6_subnet = None
    __racs_route6_prefix = None

    __remote_nameservers = None

    __hosts = None

    __wintun = None

    # 最近接收数据的时间
    __last_recv_data_time = None

    @property
    def https_configs(self):
        configs = self.__configs.get("tunnel_over_https", {})
        enable_https_sni = bool(int(configs.get("enable_https_sni", 0)))
        https_sni_host = configs.get("https_sni_host", "")
        strict_https = bool(int(configs.get("strict_https", "0")))
        ciphers = configs.get("ciphers", "NULL")

        if ciphers.upper() != "NULL":
            if ciphers[-1] == ",": ciphers = ciphers[0:-1]
            ciphers = ciphers.strip()
            if not ciphers:
                ciphers = "NULL"
            else:
                _list = ciphers.split(",")
                new_list = []
                for s in _list:
                    s = s.strip()
                    new_list.append(s)
                ciphers = ":".join(new_list)
            ''''''
        pyo = {
            "url": configs.get("url", "/"),
            "auth_id": configs.get("auth_id", "fdslight"),
            "enable_https_sni": enable_https_sni,
            "https_sni_host": https_sni_host,
            "strict_https": strict_https,
            "ciphers": ciphers,
        }

        return pyo

    def tunnel_conn_fail(self):
        self.__tunnel_conn_fail_count += 1

    def tunnel_conn_ok(self):
        self.__tunnel_conn_fail_count = 0

    @property
    def tunnel_conn_fail_count(self):
        return self.__tunnel_conn_fail_count

    def init_func(self, conf_dir):
        self.__last_recv_data_time = time.time()
        # 首先清理一次注册表,非法关闭时注册表不会清空
        self.__clear_winreg()
        self.__debug = True
        config_path = "%s/fn_client.ini" % conf_dir
        self.__conf_dir = conf_dir
        configs = configfile.ini_parse_from_file(config_path)
        self.__log_file = "%s/fdslight.log" % conf_dir
        self.__err_file = "%s/error.log" % conf_dir

        self.load_driver()

        self.create_poll()
        # 因为wintun的线程事件模型关系,这里select io阻塞时间始终为0
        # 避免无法及时收到网卡数据包
        self.set_default_io_wait_time(0)

        self.__route_timer = timer.timer()
        self.__routes = {}
        self.__configs = configs
        self.__static_routes = {}
        self.__tunnel_conn_fail_count = 0
        self.__tunnel_fileno = -1
        self.__racs_fd = -1

        # 加载fn_client.ini的远程DNS选项
        self.__remote_nameservers = [self.__configs["public"]["remote_dns"]]

        self.__hosts = {}

        self.load_hosts()
        self.load_racs_configs()

        self.__devname = self.__configs['public'].get('tun_devname', 'fdslight')

        self.__mbuf = utils.mbuf()

        public = configs["public"]

        self.__enable_ipv6_traffic = bool(int(public["enable_ipv6_traffic"]))
        enable_ipv6_dns_drop = bool(int(public.get("enable_ipv6_dns_drop", "0")))

        is_ipv6 = utils.is_ipv6_address(public["remote_dns"])

        self.__enable_dot = bool(int(public.get("enable_dot", "0")))
        dot_auth_host = public.get("dot_auth_host", public["remote_dns"])
        self.__dot_auth_host = dot_auth_host
        self.__dot_host = public['remote_dns']

        if self.__enable_dot:
            self.__dot_fileno = self.create_handler(-1, dns_proxy.dot_client, public['remote_dns'], dot_auth_host,
                                                    is_ipv6=is_ipv6, debug=self.debug)
        self.__dns_fileno = self.create_handler(-1, dns_proxy.dnsc_proxy, public["remote_dns"], is_ipv6=is_ipv6,
                                                debug=self.debug,
                                                server_side=False, enable_ipv6_dns_drop=enable_ipv6_dns_drop)

        self.get_handler(self.__dns_fileno).set_parent_dnsserver(public["remote_dns"],
                                                                 is_ipv6=is_ipv6)
        self.__set_rules()
        local = configs["local"]

        vir_dns = local["virtual_dns"]
        vir_dns6 = local["virtual_dns6"]

        self.__local_ip, self.__local_ip_prefix = netutils.parse_ip_with_prefix(local["local_ip"])
        self.__local_ip6, self.__local_ip6_prefix = netutils.parse_ip_with_prefix(local["local_ip6"])

        self.__byte_local_ip = socket.inet_pton(socket.AF_INET, self.__local_ip)
        self.__byte_local_ip6 = socket.inet_pton(socket.AF_INET6, self.__local_ip6)

        self.__local_dns = vir_dns
        self.__local_dns6 = vir_dns6

        conn = configs["connection"]

        m = "freenet.lib.crypto.%s" % conn["crypto_module"]
        try:
            self.__tcp_crypto = importlib.import_module("%s.%s_tcp" % (m, conn["crypto_module"]))
            self.__udp_crypto = importlib.import_module("%s.%s_udp" % (m, conn["crypto_module"]))
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        crypto_fpath = "%s/%s" % (conf_dir, conn["crypto_configfile"])

        if not os.path.isfile(crypto_fpath):
            print("crypto configfile not exists")
            sys.exit(-1)

        try:
            crypto_configs = proto_utils.load_crypto_configfile(crypto_fpath)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        self.__crypto_configs = crypto_configs

        # 如果服务端为UDP NAT地址,那么打开通道,避免一开始网络不通要过一段时间才通的情况
        server_host_from_nat = bool(int(conn.get("server_host_from_nat", 0)))
        tunnel_type = conn["tunnel_type"].lower()

        if tunnel_type == "udp" and server_host_from_nat:
            self.__open_tunnel()

        self.__cfg_os_net_forward()

    def load_driver(self):
        machine = platform.machine().lower()
        # 限制支持ARM64与AMD64的windows
        if machine == 'aarch64':
            driver_path = "%s/driver/wintun/arm64/wintun.dll" % BASE_DIR
        else:
            driver_path = "%s/driver/wintun/amd64/wintun.dll" % BASE_DIR

        self.__wintun = wintun_wrapper.Wintun(driver_path, ignore_cmd_output=True)

    def __cfg_os_net_forward(self):
        """配置操作系统网络重定向
        """
        self.__wintun.create_adapater(self.__devname, "fdslight")
        self.__wintun.start_session()

        self.__wintun.set_ip(self.__local_ip, int(self.__local_ip_prefix), dnsserver=self.__local_dns)
        self.__wintun.set_ip(self.__local_ip6, int(self.__local_ip6_prefix), dnsserver=self.__local_dns6, is_ipv6=True)

        self.set_route(self.__local_dns, is_ipv6=False, is_dynamic=False)

        if self.__enable_ipv6_traffic: self.set_route(self.__local_dns6, is_ipv6=True, is_dynamic=False)

    def send_packet_to_wintun(self, byte_data: bytes):
        # 限制接收的数据包大小
        if len(byte_data) > 1500: return

        self.__wintun.write(byte_data)

    def handle_msg_from_tundev(self, message):
        """处理来TUN设备的数据包
        :param message:
        :return:
        """
        # 如果网卡数据为空那么跳过
        if not message: return

        self.__mbuf.copy2buf(message)

        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        if ip_ver == 4:
            dst_addr = message[16:20]
            is_ipv6 = False
            # 丢弃组播数据包
            if dst_addr[0] >= 224 and dst_addr[0] <= 239: return
        else:
            dst_addr = message[24:40]
            is_ipv6 = True
            # 丢弃组播数据包
            if dst_addr[0] == 0xff: return

        is_racs_network = False
        if self.racs_configs["connection"]["enable"]:
            if is_ipv6 and self.racs_configs["network"]["enable_ip6"]:
                dst_addr_s = socket.inet_ntop(socket.AF_INET6, dst_addr)
                is_racs_network = netutils.is_subnet(dst_addr_s, self.__racs_route6_prefix,
                                                     self.__racs_route_subnet, is_ipv6=is_ipv6)
            else:
                if not is_ipv6:
                    dst_addr_s = socket.inet_ntop(socket.AF_INET, dst_addr)
                    is_racs_network = netutils.is_subnet(dst_addr_s, self.__racs_route_prefix,
                                                         self.__racs_route_subnet, is_ipv6=is_ipv6)
                    ''''''
                ''''''
            if is_racs_network:
                message = self.rewrite_racs_local_ip(message, is_src=True)
                if self.__racs_fd > 0:
                    self.get_handler(self.__racs_fd).send_msg(message)
                return
            ''''''
        action = proto_utils.ACT_IPDATA
        is_ipv6 = False

        if ip_ver == 4:
            self.__mbuf.offset = 9
            nexthdr = self.__mbuf.get_part(1)
            self.__mbuf.offset = 16
            byte_daddr = self.__mbuf.get_part(4)
            fa = socket.AF_INET
        else:
            is_ipv6 = True
            self.__mbuf.offset = 6
            nexthdr = self.__mbuf.get_part(1)
            self.__mbuf.offset = 24
            byte_daddr = self.__mbuf.get_part(16)
            fa = socket.AF_INET6

        if not is_ipv6:
            if byte_daddr[0] == 0xff: return
        else:
            if byte_daddr[0] & 0xf0 == 0xf0: return

        sts_daddr = socket.inet_ntop(fa, byte_daddr)
        # 丢弃不支持的传输层包
        if ip_ver == 4 and nexthdr not in self.__support_ip4_protocols: return
        if ip_ver == 6 and nexthdr not in self.__support_ip6_protocols: return

        is_dns_req, saddr, daddr, sport, rs = self.__is_dns_request()

        if is_dns_req:
            self.get_handler(self.__dns_fileno).dnsmsg_from_tun(saddr, daddr, sport, rs, is_ipv6=is_ipv6)
            return

        self.__update_route_access(sts_daddr)
        self.send_msg_to_tunnel(action, message)

    def handle_msg_from_tunnel(self, seession_id, action, message):
        self.__last_recv_data_time = time.time()

        if seession_id != self.session_id: return
        if action not in proto_utils.ACTS: return

        if action == proto_utils.ACT_ZLIB_IPDATA or action == proto_utils.ACT_ZLIB_DNS:
            try:
                message = zlib.decompress(message)
            except zlib.error:
                return

            if action == proto_utils.ACT_ZLIB_IPDATA:
                action = proto_utils.ACT_IPDATA
            else:
                action = proto_utils.ACT_DNS
            ''''''
        if action == proto_utils.ACT_DNS:
            self.get_handler(self.__dns_fileno).msg_from_tunnel(message)
            return
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        self.send_msg_to_tun(message)

    def send_msg_to_other_dnsservice_for_dns_response(self, message, is_ipv6=False):
        """当启用IPV4和IPv6双协议栈的时候
        此函数的作用是两个局域网DNS服务相互发送消息
        :param message:
        :param is_ipv6:发送的目标是否是IPv6 DNS服务
        :return:
        """
        # 没有开启IPv6的时候,禁止向另外的DNS服务发送消息
        if not self.__enable_ipv6_traffic: return
        if is_ipv6:
            fileno = self.__dns_listen6
        else:
            fileno = self.__dns_fileno

        self.send_message_to_handler(-1, fileno, message)

    def send_msg_to_tunnel(self, action, message):
        if not self.handler_exists(self.__tunnel_fileno):
            self.__open_tunnel()

        if not self.handler_exists(self.__tunnel_fileno): return

        # 压缩DNS和IPDATA数据
        if action in (proto_utils.ACT_IPDATA, proto_utils.ACT_DNS,):
            length = len(message)
            new_msg = zlib.compress(message)
            comp_length = len(new_msg)

            if comp_length < length:
                message = new_msg
                if action == proto_utils.ACT_IPDATA:
                    action = proto_utils.ACT_ZLIB_IPDATA
                else:
                    action = proto_utils.ACT_ZLIB_DNS
                ''''''
            ''''''
        handler = self.get_handler(self.__tunnel_fileno)
        handler.send_msg_to_tunnel(self.session_id, action, message)

    def send_msg_to_tun(self, message):
        message = self.rewrite_racs_local_ip(message, is_src=False)
        self.send_packet_to_wintun(message)

    def __is_dns_request(self):
        mbuf = self.__mbuf
        ip_ver = mbuf.ip_version()

        if ip_ver == 4:
            mbuf.offset = 0
            n = mbuf.get_part(1)
            hdrlen = (n & 0x0f) * 4

            mbuf.offset = 9
            nexthdr = mbuf.get_part(1)

            mbuf.offset = 12
            saddr = mbuf.get_part(4)
            mbuf.offset = 16
            daddr = mbuf.get_part(4)
        else:
            mbuf.offset = 6
            nexthdr = mbuf.get_part(1)
            hdrlen = 40
            mbuf.offset = 8
            saddr = mbuf.get_part(16)
            mbuf.offset = 24
            daddr = mbuf.get_part(16)

        if (nexthdr != 17): return (False, None, None, None, None)

        mbuf.offset = hdrlen
        sport = utils.bytes2number(mbuf.get_part(2))

        mbuf.offset = hdrlen + 2
        dport = utils.bytes2number(mbuf.get_part(2))
        if dport != 53: return (False, None, None, None, None,)

        mbuf.offset = hdrlen + 8

        return (True, saddr, daddr, sport, mbuf.get_data(),)

    @property
    def session_id(self):
        if not self.__session_id:
            connection = self.__configs["connection"]
            username = connection["username"]
            passwd = connection["password"]

            self.__session_id = proto_utils.gen_session_id(username, passwd)

        return self.__session_id

    @property
    def hosts(self):
        return self.__hosts

    def load_hosts(self):
        self.__hosts = {
            "A": {},
            "AAAA": {}
        }

        path = "%s/hosts.json" % self.__conf_dir
        if not os.path.isfile(path):
            logging.print_error("not found %s hosts file" % path)
            return
        with open(path, "r") as f:
            s = f.read()
        f.close()

        try:
            hosts = json.loads(s)
        except json.JSONDecoder:
            logging.print_error("wrong file hosts file format %s" % path)
            return

        if not isinstance(hosts, dict):
            logging.print_error("wrong file hosts file format %s,it must be dict" % path)
            return

        if "A" not in hosts: hosts["A"] = {}
        if "AAAA" not in hosts: hosts["AAAA"] = {}

        if not isinstance(hosts['A'], dict):
            logging.print_error("wrong file hosts file A record format %s,it must be dict" % path)
            return

        if not isinstance(hosts['AAAA'], dict):
            logging.print_error("wrong file hosts file AAAA record format %s,it must be dict" % path)
            return

        for host, addr in hosts['A'].items():
            if not netutils.is_ipv4_address(addr):
                logging.print_error("wrong file hosts file A record IP address format %s %s" % (path, addr))
                return
            continue

        for host, addr in hosts['AAAA'].items():
            if not netutils.is_ipv6_address(addr):
                logging.print_error("wrong file hosts file AAAArecord IP address format %s %s" % (path, addr))
                return
            continue
        self.__hosts = hosts

    def __set_rules(self):
        self.load_hosts()
        fpaths = [
            "%s/host_rules.txt" % self.__conf_dir,
            "%s/ip_rules.txt" % self.__conf_dir,
            "%s/pre_load_ip_rules.txt" % self.__conf_dir
        ]

        for fpath in fpaths:
            if not os.path.isfile(fpath):
                sys.stderr.write("cannot found %s\r\n" % fpath)
                return
            ''''''
        try:
            rules = file_parser.parse_host_file(fpaths[0])
            self.get_handler(self.__dns_fileno).set_host_rules(rules)

            rules = file_parser.parse_ip_subnet_file(fpaths[1])
            self.get_handler(self.__dns_fileno).set_ip_rules(rules)

            rules = file_parser.parse_ip_subnet_file(fpaths[2])
            self.__set_static_ip_rules(rules)

        except file_parser.FilefmtErr:
            logging.print_error()

    def __set_static_ip_rules(self, rules):
        nameserver = self.__configs["public"]["remote_dns"]
        ns_is_ipv6 = utils.is_ipv6_address(nameserver)

        # 查看新的规则
        kv_pairs_new = {}
        for subnet, prefix in rules:
            if not utils.is_ipv6_address(subnet) and not utils.is_ipv4_address(subnet):
                logging.print_error("wrong pre ip rule %s/%s" % (subnet, prefix,))
                continue
            is_ipv6 = utils.is_ipv6_address(subnet)

            # 找到和nameserver冲突的路由那么跳过,这里需要判断IP地址类型是否一致
            if ns_is_ipv6 == is_ipv6:
                t = utils.calc_subnet(nameserver, prefix, is_ipv6=ns_is_ipv6)
                if t == subnet:
                    logging.print_error(
                        "conflict preload ip rules %s/%s with nameserver %s" % (subnet, prefix, nameserver,)
                    )
                    continue
                ''''''
            name = "%s/%s" % (subnet, prefix,)
            kv_pairs_new[name] = (subnet, prefix, is_ipv6,)
        # 需要删除的列表
        need_dels = []
        # 需要增加的路由
        need_adds = []

        for name in kv_pairs_new:
            # 新的规则旧的没有那么就需要添加
            if name not in self.__static_routes:
                need_adds.append(kv_pairs_new[name])

        for name in self.__static_routes:
            # 旧的规则新的没有,那么就是需要删除
            if name not in kv_pairs_new:
                need_dels.append(self.__static_routes[name])

        # 删除需要删除的路由
        for subnet, prefix, is_ipv6 in need_dels:
            # 略过racs路由
            if self.is_racs_route(subnet, prefix, is_ipv6=is_ipv6): continue
            self.__del_route(subnet, prefix=prefix, is_ipv6=is_ipv6, is_dynamic=False)
        # 增加需要增加的路由
        for subnet, prefix, is_ipv6 in need_adds:
            self.set_route(subnet, prefix=prefix, is_ipv6=is_ipv6, is_dynamic=False)

    def __open_tunnel(self):
        conn = self.__configs["connection"]
        host = conn["host"]
        port = int(conn["port"])
        enable_ipv6 = bool(int(conn["enable_ipv6"]))
        conn_timeout = int(conn["conn_timeout"])
        tunnel_type = conn["tunnel_type"]
        redundancy = bool(int(conn.get("udp_tunnel_redundancy", 1)))
        over_https = bool(int(conn.get("tunnel_over_https", 0)))

        use_https = False

        server_host_from_nat = bool(int(conn.get("server_host_from_nat", 0)))

        only_permit_send_udp_data_when_first_recv_peer = bool(
            int(conn.get("only_permit_send_udp_data_when_first_recv_peer", 0)))

        bind_udp_local_port = int(conn.get("bind_udp_local_port", 0))

        if bind_udp_local_port != 0 and not netutils.is_port_number(bind_udp_local_port):
            logging.print_error("wrong bind udp local port value %s" % bind_udp_local_port)
            return

        is_udp = False

        enable_heartbeat = bool(int(conn.get("enable_heartbeat", 0)))
        heartbeat_timeout = int(conn.get("heartbeat_timeout", 15))
        if heartbeat_timeout < 10:
            raise ValueError("wrong heartbeat_timeout value from config")

        if tunnel_type.lower() == "udp":
            handler = tunnelc.udp_tunnel
            crypto = self.__udp_crypto
            is_udp = True
        else:
            handler = tunnelc.tcp_tunnel
            crypto = self.__tcp_crypto
            if over_https:
                crypto = tunnel_over_http
                use_https = True
            ''''''

        if conn_timeout < 120:
            raise ValueError("the conn timeout must be more than 120s")

        if enable_heartbeat and conn_timeout - heartbeat_timeout < 30:
            raise ValueError("the headerbeat_timeout value wrong")

        kwargs = {"conn_timeout": conn_timeout, "is_ipv6": enable_ipv6, "enable_heartbeat": enable_heartbeat,
                  "heartbeat_timeout": heartbeat_timeout, "host": host}

        if not is_udp:
            kwargs["tunnel_over_https"] = over_https
        else:
            kwargs["bind_udp_local_port"] = bind_udp_local_port
            kwargs["only_permit_send_udp_data_when_first_recv_peer"] = only_permit_send_udp_data_when_first_recv_peer
            kwargs["server_host_from_nat"] = server_host_from_nat

        if tunnel_type.lower() == "udp": kwargs["redundancy"] = redundancy

        if use_https:
            self.__tunnel_fileno = self.create_handler(-1, handler, crypto, None, **kwargs)
            self.get_handler(self.__tunnel_fileno).set_use_http_thin_protocol(True)
        else:
            self.__tunnel_fileno = self.create_handler(-1, handler, crypto, self.__crypto_configs, **kwargs)

        rs = self.get_handler(self.__tunnel_fileno).create_tunnel((host, port,))
        if not rs:
            self.delete_handler(self.__tunnel_fileno)

    def __get_conflict_from_static_route(self, ipaddr, is_ipv6=False):
        """获取与static冲突的结果
        :param ipaddr:
        :param is_ipv6:
        :return:
        """
        if is_ipv6:
            n = 128
        else:
            n = 32

        rs = None

        while n > 0:
            sub = utils.calc_subnet(ipaddr, n, is_ipv6=is_ipv6)
            name = "%s/%s" % (sub, n,)
            if name in self.__static_routes:
                rs = self.__static_routes[name]
                break
            n -= 1
        return rs

    def tell_tunnel_close(self):
        self.__tunnel_fileno = -1

    def tell_dot_close(self):
        self.__dot_fileno = -1

    def tell_racs_close(self):
        self.__racs_fd = -1

    def get_server_ip(self, host):
        """获取服务器IP
        :param host:
        :return:
        """
        self.__server_ip = host

        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        enable_ipv6 = bool(int(self.__configs["connection"]["enable_ipv6"]))
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.__remote_nameservers

        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            try:
                if enable_ipv6:
                    rs = resolver.resolve(host, "AAAA")
                else:
                    rs = resolver.resolve(host, "A")
                ''''''
            except AttributeError:
                try:
                    if enable_ipv6:
                        rs = resolver.query(host, "AAAA")
                    else:
                        rs = resolver.query(host, "A")
                    ''''''
                except:
                    return None
                ''''''
        except:
            return None

        ipaddr = None

        for anwser in rs:
            ipaddr = anwser.__str__()
            break

        self.__server_ip = ipaddr
        if not ipaddr: return ipaddr
        # 检查路由是否冲突
        rs = self.__get_conflict_from_static_route(ipaddr, is_ipv6=enable_ipv6)
        # 路由冲突那么先删除路由
        if rs:
            self.__del_route(rs[0], prefix=rs[1], is_ipv6=rs[2], is_dynamic=False)
            logging.print_error("conflict route with tunnel ip,it is %s/%s" % (rs[0], rs[1],))

        if ipaddr in self.__routes:
            self.__del_route(ipaddr, is_dynamic=True, is_ipv6=enable_ipv6)

        return ipaddr

    @property
    def debug(self):
        return self.__debug

    def myloop(self):
        now = time.time()
        # 通过不断主动轮询读取网卡数据
        tun_recv_data = self.__wintun.read()
        self.handle_msg_from_tundev(tun_recv_data)

        # 如果数据大于指定时间没收到数据,那么等待一段时间,减少CPU时间占用
        if now - self.__last_recv_data_time > 3:
            self.__wintun.wait_read_event(1000)
        ''''''

        names = self.__route_timer.get_timeout_names()
        for name in names: self.__del_route(name)

        if self.__racs_cfg["connection"]["enable"]:
            self.racs_reset()

    def set_route(self, host, prefix=None, timeout=None, is_ipv6=False, is_dynamic=True):
        if host in self.__routes: return
        # 如果是服务器的地址,那么不设置路由,避免使用ip_rules规则的时候进入死循环,因为服务器地址可能不在ip_rules文件中
        if host == self.__server_ip: return

        # 检查路由是否和nameserver冲突,如果冲突那么不添加路由
        nameserver = self.__configs["public"]["remote_dns"]
        if nameserver == host: return

        # 如果禁止了IPV6流量,那么不设置IPV6路由
        if not self.__enable_ipv6_traffic and is_ipv6: return
        if is_ipv6:
            if prefix is None: prefix = 128
        else:
            if prefix is None: prefix = 32

        if is_ipv6:
            n = 128
        else:
            n = 32

        # 首先查看是否已经加了永久路由
        while n > 0:
            subnet = utils.calc_subnet(host, n, is_ipv6=is_ipv6)
            name = "%s/%s" % (subnet, n)
            n -= 1
            # 找到永久路由的记录就直接返回,避免冲突
            if name not in self.__static_routes: continue
            return

        self.__wintun.create_route(host, prefix, is_ipv6=is_ipv6)

        if not is_dynamic:
            name = "%s/%s" % (host, prefix,)
            self.__static_routes[name] = (host, prefix, is_ipv6,)
            return

        if not timeout: timeout = self.__ROUTE_TIMEOUT

        self.__route_timer.set_timeout(host, timeout)
        self.__routes[host] = is_ipv6

    def __del_route(self, host, prefix=None, is_ipv6=False, is_dynamic=True):
        if host not in self.__routes and is_dynamic: return
        # 当为local模式时禁止删除dns路由
        if host == self.__local_dns6 or host == self.__local_dns: return

        if is_dynamic: is_ipv6 = self.__routes[host]

        if is_ipv6:
            if not prefix: prefix = 128
        else:
            if not prefix: prefix = 32

        self.__wintun.delete_route(host, prefix, is_ipv6=is_ipv6)

        if is_dynamic:
            self.__route_timer.drop(host)
            del self.__routes[host]
        else:
            name = "%s/%s" % (host, prefix,)
            del self.__static_routes[name]

    def __update_route_access(self, host, timeout=None):
        """更新路由访问时间
        :param host:
        :param timeout:如果没有指定,那么使用默认超时
        :return:
        """
        if host not in self.__routes: return
        if not timeout:
            timeout = self.__ROUTE_TIMEOUT
        self.__route_timer.set_timeout(host, timeout)

    def __clear_routes(self):
        """清除所有的路由
        """
        for k in self.__routes:
            is_ipv6 = self.__routes[k]
            if is_ipv6:
                prefix = 128
            else:
                prefix = 32
            self.__wintun.delete_route(k, prefix, is_ipv6=is_ipv6)
        for k in self.__static_routes:
            network, prefix, is_ipv6 = self.__static_routes[k]
            self.__wintun.delete_route(network, prefix, is_ipv6=is_ipv6)
        ''''''

    def __clear_winreg(self):
        """清除注册表相关适配器信息,避免适配器在注册表一直增多
        """
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)

        sub_num, key_num, _ = winreg.QueryInfoKey(reg)
        dels = []

        for i in range(sub_num):
            sub_key = winreg.EnumKey(reg, i)
            t = path + '\\' + sub_key
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, t)
            _sub_num, _key_num, _ = winreg.QueryInfoKey(k)
            for j in range(_key_num):
                r = winreg.EnumValue(k, j)
                if r[0].lower() == "description":
                    if r[1] == "fdslight":
                        dels.append(sub_key)
                    ''''''
                ''''''
            ''''''
        for sub_key in dels:
            winreg.DeleteKey(reg, sub_key)

    def release(self):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)

        self.__clear_routes()

        self.__wintun.end_session()
        self.__wintun.close_adapter()
        self.__wintun.delete_driver()
        self.__clear_winreg()

    @property
    def ca_path(self):
        """获取CA路径
        :return:
        """
        path = "%s/cadata/ca-bundle.crt" % BASE_DIR
        return path

    @property
    def dns_fd(self):
        return self.__dns_fileno

    @property
    def dot_fd(self):
        return self.__dot_fileno

    @property
    def enable_dot(self):
        return self.__enable_dot

    def dot_open(self):
        is_ipv6 = netutils.is_ipv6_address(self.__dot_host)
        self.__dot_fileno = self.create_handler(-1, dns_proxy.dot_client, self.__dot_host, self.__dot_auth_host,
                                                is_ipv6=is_ipv6, debug=self.__debug)

    def is_racs_route(self, subnet, prefix, is_ipv6=False):
        """检查是否是racs路由
        :param subnet:
        :param prefix:
        :param is_ipv6:
        :return:
        """
        conn = self.__racs_cfg["connection"]
        if not conn["enable"]: return False
        network = self.__racs_cfg["network"]
        ip_route = network["ip_route"]
        ip6_route = network["ip6_route"]

        s = "%s/%s" % (subnet, prefix)
        if is_ipv6: return s == ip6_route

        return s == ip_route

    def rewrite_racs_local_ip(self, netpkt: bytes, is_src=False):
        version = (netpkt[0] & 0xf0) >> 4
        network = self.racs_configs["network"]

        need_rewrite = True

        if version == 6:
            is_ipv6 = True
            if is_src:
                byte_addr = netpkt[8:24]
            else:
                byte_addr = netpkt[24:40]
            rewrite_local_addr = network["byte_local_rewrite_ip6"]
            if rewrite_local_addr == bytes(16): need_rewrite = False
        else:
            is_ipv6 = False
            if is_src:
                byte_addr = netpkt[12:16]
            else:
                byte_addr = netpkt[16:20]
            rewrite_local_addr = network["byte_local_rewrite_ip"]
            if rewrite_local_addr == bytes(4): need_rewrite = False

        # 如果不需要重写,就直接返回
        if not need_rewrite: return netpkt
        if not is_src and byte_addr != rewrite_local_addr: return netpkt

        mbuf = utils.mbuf()
        mbuf.copy2buf(netpkt)

        if is_src:
            if is_ipv6:
                ippkts.modify_ip6address(rewrite_local_addr, mbuf, 0)
            else:
                ippkts.modify_ip4address(rewrite_local_addr, mbuf, 0)

            mbuf.offset = 0
            netpkt = mbuf.get_data()

            return netpkt

        if is_ipv6:
            ippkts.modify_ip6address(self.__byte_local_ip6, mbuf, 1)

            mbuf.offset = 0
            netpkt = mbuf.get_data()

            return netpkt

        if not self.__byte_local_ip: return netpkt

        ippkts.modify_ip4address(self.__byte_local_ip, mbuf, 1)
        mbuf.offset = 0
        netpkt = mbuf.get_data()

        return netpkt

    def racs_reset(self):
        if self.__racs_fd > 0: return

        self.load_racs_configs()

        conn = self.__racs_cfg["connection"]
        security = self.__racs_cfg["security"]
        network = self.__racs_cfg["network"]
        _type = conn["tunnel_type"].lower()

        if _type not in ("tcp", "udp",):
            tunnel_type = "udp"
        else:
            tunnel_type = _type

        if tunnel_type == "udp":
            h = racs.udp_tunnel
        else:
            h = racs.tcp_tunnel

        if conn["enable_ip6"]:
            self.__racs_fd = self.create_handler(-1, h, (conn["host"], int(conn["port"]),), is_ipv6=True)
        else:
            self.__racs_fd = self.create_handler(-1, h, (conn["host"], int(conn["port"]),), is_ipv6=False)

        if self.__racs_fd < 0: return

        self.get_handler(self.__racs_fd).set_key(security["shared_key"])
        self.get_handler(self.__racs_fd).set_priv_key(security["private_key"])

        if network["enable_ip6"]:
            host, prefix = netutils.parse_ip_with_prefix(network["ip6_route"])
            self.set_route(host, prefix, is_ipv6=True, is_dynamic=False)
        host, prefix = netutils.parse_ip_with_prefix(network["ip_route"])
        if not self.racs_configs["connection"]["enable"]: return
        self.set_route(host, prefix, is_ipv6=False, is_dynamic=False)

    @property
    def racs_configs(self):
        return self.__racs_cfg

    def get_racs_server_ip(self, host, enable_ipv6=False):
        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        resolver = dns.resolver.Resolver()

        resolver.nameservers = self.__remote_nameservers
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            try:
                if enable_ipv6:
                    rs = resolver.resolve(host, "AAAA")
                else:
                    rs = resolver.resolve(host, "A")
                ''''''
            except AttributeError:
                try:
                    if enable_ipv6:
                        rs = resolver.query(host, "AAAA")
                    else:
                        rs = resolver.query(host, "A")
                    ''''''
                except:
                    return None
                ''''''
        except:
            return None

        ipaddr = None

        for anwser in rs:
            ipaddr = anwser.__str__()
            break

        return ipaddr

    def load_racs_configs(self):
        fpath = "%s/racs.ini" % self.__conf_dir
        configs = configfile.ini_parse_from_file(fpath)
        conn = configs["connection"]
        network = configs["network"]

        conn["enable"] = bool(int(conn["enable"]))
        conn["enable_ip6"] = bool(int(conn["enable_ip6"]))

        network["enable_ip6"] = bool(int(network["enable_ip6"]))

        local_rewrite_ip = network.get("local_rewrite_ip", "0.0.0.0")
        local_rewrite_ip6 = network.get("local_rewrite_ip6", "::")

        host, prefix = netutils.parse_ip_with_prefix(network["ip_route"])
        self.__racs_route_subnet = host
        self.__racs_route_prefix = int(prefix)

        host, prefix = netutils.parse_ip_with_prefix(network["ip6_route"])
        self.__racs_route6_subnet = host
        self.__racs_route6_prefix = int(prefix)

        network["byte_local_rewrite_ip"] = socket.inet_pton(socket.AF_INET, local_rewrite_ip)
        network["byte_local_rewrite_ip6"] = socket.inet_pton(socket.AF_INET6, local_rewrite_ip6)

        self.__racs_cfg = configs

    def send_to_local(self, msg: bytes):
        self.send_msg_to_tun(msg)


def __start_service(conf_dir):
    cls = fdslight_client()

    try:
        cls.ioloop(conf_dir)
    except KeyboardInterrupt:
        cls.release()
    ''''''


def __is_admin():
    rs = ctypes.windll.shell32.IsUserAnAdmin()
    if not rs: return False

    return True


def main():
    c = "%s/fdslight_etc" % BASE_DIR
    if len(sys.argv) < 2:
        print("NOTE:not set your configure directory,will be use default directory %s" % c)

    if len(sys.argv) > 2:
        print("ERROR:wrong start cmd")
        return

    if len(sys.argv) == 2:
        c = "%s/%s" % (BASE_DIR, sys.argv[1])

    if not os.path.isdir(c):
        print("ERROR:configure %s not is a directory" % c)
        return

    # 需要管理员权限运行此程序
    if not __is_admin():
        print("ERROR:the software need administrator privileges")
        return

    print("NOTE:use configure directory %s" % c)
    __start_service(c)


if __name__ == '__main__': main()
