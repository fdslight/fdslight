#!/usr/bin/env python3

import sys, os, time, json

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.timer as timer
import pywind.lib.configfile as configfile
import pywind.lib.netutils as netutils
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.proc as proc
import freenet.handlers.tundev as tundev
import os, getopt, signal, importlib, socket
import freenet.handlers.dns_proxy as dns_proxy
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.handlers.tunnelc as tunnelc
import freenet.lib.file_parser as file_parser
import freenet.handlers.traffic_pass as traffic_pass
import freenet.lib.logging as logging
import freenet.lib.racs_cext as racs_cext
import freenet.lib.os_resolv as os_resolv
import freenet.handlers.racs as racs
import dns.resolver

_MODE_GW = 1
_MODE_LOCAL = 2

# 自动日志清理时间
AUTO_LOG_CLEAN_TIME = 3600

PID_FILE = "/tmp/fdslight.pid"
LOG_FILE = "/tmp/fdslight.log"
ERR_FILE = "/tmp/fdslight_error.log"


class _fdslight_client(dispatcher.dispatcher):
    # 路由超时时间
    __ROUTE_TIMEOUT = 1200

    # 最近日志清理时间
    __last_log_clean_time = None

    __routes = None

    __route_timer = None

    __DEVNAME = "fdslight"

    __configs = None

    __mode = 0

    __mbuf = None

    __tunnel_fileno = -1

    __dns_fileno = -1

    __dns_listen6 = -1
    __tundev_fileno = -1

    __session_id = None

    __debug = False

    __tcp_crypto = None
    __udp_crypto = None
    __crypto_configs = None

    __support_ip4_protocols = (1, 6, 17, 132, 136,)
    __support_ip6_protocols = (6, 17, 58, 132, 136,)

    __dgram_fetch_fileno = -1

    # 是否开启IPV6流量
    __enable_ipv6_traffic = False

    # 服务器地址
    __server_ip = None

    # 静态路由,即在程序运行期间一直存在
    __static_routes = None

    # 隧道尝试连接失败次数
    __tunnel_conn_fail_count = None

    __local_dns = None
    __local_dns6 = None

    __racs_fd = None
    __racs_cfg = None
    __racs_byte_network_v4 = None
    __racs_byte_network_v6 = None

    __os_resolv_backup = None
    __os_resolv = None

    __cur_traffic_size = None
    __limit_traffic_size = None
    __traffic_statistics_path = None
    __traffic_up_time = None
    __traffic_begin_time = None

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

    def init_func(self, mode, debug, configs):
        self.create_poll()

        signal.signal(signal.SIGINT, self.__exit)

        self.__route_timer = timer.timer()
        self.__last_log_clean_time = time.time()
        self.__routes = {}
        self.__configs = configs
        self.__static_routes = {}
        self.__tunnel_conn_fail_count = 0
        self.__racs_fd = -1
        self.__os_resolv_backup = []
        self.__os_resolv = os_resolv.resolv()

        self.__cur_traffic_size = 0
        self.__limit_traffic_size = 0

        self.__traffic_statistics_path = "%s/traffic.json" % BASE_DIR
        self.__traffic_up_time = time.time()
        self.__traffic_begin_time = time.time()

        self.load_traffic_statistics()
        self.load_racs_configs()

        if mode == "local":
            self.__mode = _MODE_LOCAL
            self.__os_resolv_backup = self.__os_resolv.get_os_resolv()
        else:
            self.__mode = _MODE_GW
            self.__load_kernel_mod()

        self.__mbuf = utils.mbuf()
        self.__debug = debug

        self.__tundev_fileno = self.create_handler(-1, tundev.tundevc, self.__DEVNAME)

        public = configs["public"]
        gateway = configs["gateway"]

        self.__enable_ipv6_traffic = bool(int(public["enable_ipv6_traffic"]))

        is_ipv6 = utils.is_ipv6_address(public["remote_dns"])

        if self.__mode == _MODE_GW:
            self.__dns_fileno = self.create_handler(-1, dns_proxy.dnsc_proxy, gateway["dnsserver_bind"], debug=debug,
                                                    server_side=True, is_ipv6=False)
            if self.__enable_ipv6_traffic:
                self.__dns_listen6 = self.create_handler(-1, dns_proxy.dnsc_proxy, gateway["dnsserver_bind6"],
                                                         debug=debug, server_side=True, is_ipv6=True)
                self.get_handler(self.__dns_listen6).set_parent_dnsserver(public["remote_dns"], is_ipv6=is_ipv6)
        else:
            self.__dns_fileno = self.create_handler(-1, dns_proxy.dnsc_proxy, public["remote_dns"], debug=debug,
                                                    server_side=False)
        self.get_handler(self.__dns_fileno).set_parent_dnsserver(public["remote_dns"], is_ipv6=is_ipv6)

        self.__set_rules(None, None)

        if self.__mode == _MODE_GW:
            udp_global = bool(int(gateway["dgram_global_proxy"]))
            if udp_global:
                self.__dgram_fetch_fileno = self.create_handler(-1, traffic_pass.traffic_read,
                                                                self.__configs["gateway"],
                                                                enable_ipv6=self.__enable_ipv6_traffic)
            ''''''
        else:
            local = configs["local"]
            vir_dns = local["virtual_dns"]
            vir_dns6 = local["virtual_dns6"]

            self.__local_dns = vir_dns
            self.__local_dns6 = vir_dns6

            _list = [("nameserver", vir_dns), ]

            self.__os_resolv.write_to_file(_list)

            self.set_route(vir_dns, is_ipv6=False, is_dynamic=False)
            if self.__enable_ipv6_traffic: self.set_route(vir_dns6, is_ipv6=True, is_dynamic=False)

        conn = configs["connection"]

        m = "freenet.lib.crypto.%s" % conn["crypto_module"]
        try:
            self.__tcp_crypto = importlib.import_module("%s.%s_tcp" % (m, conn["crypto_module"]))
            self.__udp_crypto = importlib.import_module("%s.%s_udp" % (m, conn["crypto_module"]))
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        crypto_fpath = "%s/fdslight_etc/%s" % (BASE_DIR, conn["crypto_configfile"])

        if not os.path.isfile(crypto_fpath):
            print("crypto configfile not exists")
            sys.exit(-1)

        try:
            crypto_configs = proto_utils.load_crypto_configfile(crypto_fpath)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        self.__crypto_configs = crypto_configs

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")
        ''''''

        signal.signal(signal.SIGUSR1, self.__set_rules)
        signal.signal(signal.SIGUSR2, self.__reset_traffic_sig)

    def __load_kernel_mod(self):
        ko_file = "%s/driver/fdslight_dgram.ko" % BASE_DIR

        if not os.path.isfile(ko_file):
            print("you must install this software")
            sys.exit(-1)

        fpath = "%s/fdslight_etc/kern_version" % BASE_DIR
        if not os.path.isfile(fpath):
            print("you must install this software")
            sys.exit(-1)

        with open(fpath, "r") as f:
            cp_ver = f.read()
            fp = os.popen("uname -r")
            now_ver = fp.read()
            fp.close()

        if cp_ver != now_ver:
            print("the kernel is changed,please reinstall this software")
            sys.exit(-1)

        path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        if os.path.exists(path): os.system("rmmod fdslight_dgram")

        # 开启ip forward
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        # 禁止接收ICMP redirect 包,防止客户端机器选择最佳路由
        os.system("echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects > /dev/null")

        if self.__enable_ipv6_traffic:
            os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")

        os.system("insmod %s" % ko_file)

    def handle_msg_from_tundev(self, message):
        """处理来TUN设备的数据包
        :param message:
        :return:
        """
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()

        if ip_ver not in (4, 6,): return

        if ip_ver == 4:
            dst_addr = message[16:20]
            is_ipv6 = False
        else:
            dst_addr = message[24:40]
            is_ipv6 = True

        if self.racs_configs["connection"]["enable"]:
            if is_ipv6 and self.racs_configs["network"]["enable_ip6"]:
                is_racs_network = racs_cext.is_same_subnet_with_msk(dst_addr, self.__racs_byte_network_v6[0],
                                                                    self.__racs_byte_network_v6[1], is_ipv6)
            else:
                is_racs_network = racs_cext.is_same_subnet_with_msk(dst_addr, self.__racs_byte_network_v4[0],
                                                                    self.__racs_byte_network_v4[1], is_ipv6)
            if is_racs_network:
                if self.__racs_fd > 0:
                    self.get_handler(self.__racs_fd).send_msg(message)
                return

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

        sts_daddr = socket.inet_ntop(fa, byte_daddr)

        # 丢弃不支持的传输层包
        if ip_ver == 4 and nexthdr not in self.__support_ip4_protocols: return
        if ip_ver == 6 and nexthdr not in self.__support_ip6_protocols: return

        if self.__mode == _MODE_LOCAL:
            is_dns_req, saddr, daddr, sport, rs = self.__is_dns_request()
            if is_dns_req:
                self.get_handler(self.__dns_fileno).dnsmsg_from_tun(saddr, daddr, sport, rs, is_ipv6=is_ipv6)
                return

        self.__update_route_access(sts_daddr)
        self.send_msg_to_tunnel(action, message)

    def handle_msg_from_dgramdev(self, message):
        """处理来自fdslight dgram设备的数据包
        :param message:
        :return:
        """
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        is_ipv6 = False

        if ip_ver == 4:
            self.__mbuf.offset = 16
            fa = socket.AF_INET
            n = 4
        else:
            self.__mbuf.offset = 24
            fa = socket.AF_INET6
            n = 16
            is_ipv6 = True

        byte_daddr = self.__mbuf.get_part(n)
        sts_daddr = socket.inet_ntop(fa, byte_daddr)

        if sts_daddr not in self.__routes:
            self.set_route(sts_daddr, timeout=190, is_ipv6=is_ipv6, is_dynamic=True)
        else:
            self.__update_route_access(sts_daddr, timeout=190)
        self.send_msg_to_tunnel(proto_utils.ACT_IPDATA, message)

    def handle_msg_from_tunnel(self, seession_id, action, message):
        if seession_id != self.session_id: return
        if action not in proto_utils.ACTS: return

        self.__cur_traffic_size += len(message)
        if not self.have_traffic(): return

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

        self.__cur_traffic_size += len(message)
        if not self.have_traffic(): return

        handler = self.get_handler(self.__tunnel_fileno)
        handler.send_msg_to_tunnel(self.session_id, action, message)

    def send_msg_to_tun(self, message):
        self.get_handler(self.__tundev_fileno).msg_from_tunnel(message)

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

    def __set_rules(self, signum, frame):
        fpaths = [
            "%s/fdslight_etc/host_rules.txt" % BASE_DIR,
            "%s/fdslight_etc/ip_rules.txt" % BASE_DIR,
            "%s/fdslight_etc/pre_load_ip_rules.txt" % BASE_DIR
        ]

        for fpath in fpaths:
            if not os.path.isfile(fpath):
                sys.stderr.write("cannot found %s\r\n" % fpath)
                return
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

        self.__limit_traffic_size = int(conn.get("traffic_limit_size", "0")) * 1024 * 1024 * 1024

        if not self.have_traffic():
            logging.print_error("not enough traffic for tunnel")
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

        if conn_timeout < 120:
            raise ValueError("the conn timeout must be more than 120s")

        if enable_heartbeat and conn_timeout - heartbeat_timeout < 30:
            raise ValueError("the headerbeat_timeout value wrong")

        kwargs = {"conn_timeout": conn_timeout, "is_ipv6": enable_ipv6, "enable_heartbeat": enable_heartbeat,
                  "heartbeat_timeout": heartbeat_timeout, "host": host}

        if not is_udp:
            kwargs["tunnel_over_https"] = over_https

        if tunnel_type.lower() == "udp": kwargs["redundancy"] = redundancy

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

    def get_server_ip(self, host):
        """获取服务器IP
        :param host:
        :return:
        """
        self.__server_ip = host

        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        enable_ipv6 = bool(int(self.__configs["connection"]["enable_ipv6"]))
        nameserves = [self.__configs["public"]["remote_dns"]]

        resolver = dns.resolver.Resolver()
        resolver.nameservers = nameserves

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
        if self.__mode == _MODE_GW: self.__set_tunnel_ip(ipaddr)

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

    def clean_log(self):
        if self.__debug: return
        sys.stdout.close()
        # 删除日志
        os.remove(LOG_FILE)
        sys.stdout = open(LOG_FILE, "a+")

    def myloop(self):
        names = self.__route_timer.get_timeout_names()
        for name in names: self.__del_route(name)

        # 自动清理日志
        t = time.time()
        if t - self.__last_log_clean_time > AUTO_LOG_CLEAN_TIME:
            self.clean_log()
            self.__last_log_clean_time = t

        if t - self.__traffic_up_time > 60:
            self.flush_traffic_statistics()
            self.reset_traffic()
            self.__traffic_up_time = t

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
            s = "-6"
            if not prefix: prefix = 128
        else:
            s = ""
            if not prefix: prefix = 32

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

        cmd = "ip %s route add %s/%s dev %s" % (s, host, prefix, self.__DEVNAME)
        os.system(cmd)

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
            s = "-6"
            if not prefix: prefix = 128
        else:
            s = ""
            if not prefix: prefix = 32

        cmd = "ip %s route del %s/%s dev %s" % (s, host, prefix, self.__DEVNAME)
        os.system(cmd)

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

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)

        if self.__mode == _MODE_GW:
            self.delete_handler(self.__dgram_fetch_fileno)
            os.chdir("%s/driver" % BASE_DIR)
            os.system("rmmod fdslight_dgram")
            os.chdir("../")
        else:
            self.__os_resolv.write_to_file(self.__os_resolv_backup)
        sys.exit(0)

    def __set_tunnel_ip(self, ip):
        """设置隧道IP地址
        :param ip:
        :return:
        """
        if self.__mode == _MODE_GW:
            self.get_handler(self.__dgram_fetch_fileno).set_tunnel_ip(ip)
        return

    @property
    def ca_path(self):
        """获取CA路径
        :return:
        """
        path = "%s/fdslight_etc/ca-bundle.crt" % BASE_DIR
        return path

    def racs_reset(self):
        if self.__racs_fd > 0:
            self.delete_handler(self.__racs_fd)
        self.__racs_fd = -1

        self.load_racs_configs()

        conn = self.__racs_cfg["connection"]
        security = self.__racs_cfg["security"]
        network = self.__racs_cfg["network"]
        _type = conn["tunnel_type"].lower()

        if _type not in ("tcp", "udp",): tunnel_type = "udp"

        if tunnel_type == "udp":
            h = racs.udp_tunnel
        else:
            h = racs.tcp_tunnel

        if conn["enable_ip6"]:
            self.__racs_fd = self.create_handler(-1, h, (conn["host"], int(conn["port"]),), is_ipv6=True)
        else:
            self.__racs_fd = self.create_handler(-1, h, (conn["host"], int(conn["port"]),), is_ipv6=False)

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

        try:
            if enable_ipv6:
                rs = resolver.query(host, "AAAA")
            else:
                rs = resolver.query(host, "A")
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except dns.resolver.NoNameservers:
            return None
        except:
            return None

        ipaddr = None

        for anwser in rs:
            ipaddr = anwser.__str__()
            break
        return ipaddr

    def load_racs_configs(self):
        fpath = "%s/fdslight_etc/racs.ini" % BASE_DIR
        configs = configfile.ini_parse_from_file(fpath)
        conn = configs["connection"]
        network = configs["network"]

        conn["enable"] = bool(int(conn["enable"]))
        conn["enable_ip6"] = bool(int(conn["enable_ip6"]))

        network["enable_ip6"] = bool(int(network["enable_ip6"]))

        host, prefix = netutils.parse_ip_with_prefix(network["ip_route"])

        self.__racs_byte_network_v4 = (
            socket.inet_pton(socket.AF_INET, host),
            socket.inet_pton(socket.AF_INET, netutils.ip_prefix_convert(int(prefix), is_ipv6=False))
        )

        host, prefix = netutils.parse_ip_with_prefix(network["ip6_route"])
        self.__racs_byte_network_v6 = (
            socket.inet_pton(socket.AF_INET6, host),
            socket.inet_pton(socket.AF_INET6, netutils.ip_prefix_convert(int(prefix), is_ipv6=True))
        )
        self.__racs_cfg = configs

    def tell_racs_close(self):
        self.__racs_fd = -1

    def send_to_local(self, msg: bytes):
        self.send_msg_to_tun(msg)

    def flush_traffic_statistics(self):
        t = time.localtime(self.__traffic_begin_time)
        s = json.dumps({"begin_time": self.__traffic_begin_time, "traffic_size": self.__cur_traffic_size,
                        "comment_used_traffic_size": "%sGB" % int(self.__cur_traffic_size / 1024 / 1024 / 1024),
                        "comment_traffic_limit": "%sGB" % int(self.__limit_traffic_size / 1024 / 1024 / 1024),
                        "comment_begin_time": "%s" % time.strftime("%Y-%m-%d %H:%M:%S", t)
                        })
        with open(self.__traffic_statistics_path, "w") as f:
            f.write(s)
        f.close()

    def load_traffic_statistics(self):
        if not os.path.isfile(self.__traffic_statistics_path):
            self.__traffic_begin_time = time.time()
            self.__cur_traffic_size = 0
            return

        with open(self.__traffic_statistics_path, "r") as f:
            s = f.read()
        f.close()

        dic = json.loads(s)
        self.__traffic_begin_time = int(dic["begin_time"])
        self.__cur_traffic_size = int(dic["traffic_size"])

    def reset_traffic(self):
        now = time.time()
        if now - self.__traffic_begin_time > 86400 * 30:
            self.__traffic_begin_time = now
            self.__cur_traffic_size = 0
            return
        ''''''

    def have_traffic(self):
        """是否还有流量
        """
        if self.__limit_traffic_size <= 0: return True
        if self.__cur_traffic_size >= self.__limit_traffic_size: return False

        return True

    def __reset_traffic_sig(self, signum, frame):
        now = time.time()
        self.__cur_traffic_size = 0
        self.__traffic_begin_time = now


def __start_service(mode, debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the fdsl_client process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    config_path = "%s/fdslight_etc/fn_client.ini" % BASE_DIR

    configs = configfile.ini_parse_from_file(config_path)

    cls = _fdslight_client()

    if debug:
        cls.ioloop(mode, debug, configs)
        return
    try:
        cls.ioloop(mode, debug, configs)
    except:
        logging.print_error()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)
    if pid < 0: return

    os.kill(pid, signal.SIGINT)


def __update_rules():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("fdslight process not exists")
        return

    os.kill(pid, signal.SIGUSR1)


def __reset_traffic():
    pid = proc.get_pid(PID_FILE)
    if pid < 0:
        print("fdslight process not exists")
        return

    os.kill(pid, signal.SIGUSR2)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -m      local | gateway         run as local or gateway
    -u      rules | reset_traffic    update host and ip rules or reset traffic
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""
    m = ""
    u = ""

    for k, v in opts:
        if k == "-u":
            u = v
            break

        if k == "-m": m = v
        if k == "-d": d = v

    if not d and not m and not u:
        print(help_doc)
        return

    if u and u not in ("rules", "reset_traffic",):
        print(help_doc)
        return
    if u == "rules":
        __update_rules()
        return
    if u == "reset_traffic":
        __reset_traffic()
        return

    if d not in ("debug", "start", "stop",):
        print(help_doc)
        return

    if m not in ("local", "gateway"):
        print(help_doc)
        return

    if d in ("start", "debug",):
        debug = False
        if d == "debug": debug = True
        __start_service(m, debug)
        return

    if d == "stop": __stop_service()


if __name__ == '__main__': main()
