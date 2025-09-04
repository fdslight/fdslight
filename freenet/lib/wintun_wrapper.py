#!/usr/bin/env python3

import ctypes, os, hashlib
import ctypes.wintypes as wintypes
import pywind.lib.netutils as netutils


class Wintun(object):
    __wintun = None
    __adapter = None
    __session = None
    __nic_name = None
    __my_ipv4 = None
    __my_ipv6 = None
    __if_idx = None
    __ignore_cmd_output = None
    __os_nic_md5 = None

    def __init__(self, dll_path: str, ignore_cmd_output=False):
        self.__os_nic_md5 = b""
        self.__nic_name = "fdslight"
        self.__ignore_cmd_output = ignore_cmd_output
        self.__wintun = ctypes.CDLL(dll_path)

    def __exe_cmd(self, cmd):
        if not self.__ignore_cmd_output:
            os.system(cmd)
            return
        cmd += " 2>nul"
        fd = os.popen(cmd)
        fd.close()

    def __set_if_idx(self):
        # 获取接口索引
        cmd = "netsh int ipv4 show interfaces | findstr %s" % self.__nic_name
        fdst = os.popen(cmd)
        s = fdst.read()
        fdst.close()
        s = s.replace("\r", "")
        s = s.replace("\n", "")
        _list = s.split(" ")
        new_list = []
        for x in _list:
            if not x: continue
            new_list.append(x)

        self.__if_idx = new_list[0]

    def create_adapater(self, name: str, tunnel_type: str):
        self.__adapter = self.__open_adapater(name)
        self.__nic_name = name
        if not self.__adapter:
            self.__wintun.WintunCreateAdapter.restype = ctypes.c_void_p
            adapter = self.__wintun.WintunCreateAdapter(name, tunnel_type, None)
            self.__adapter = adapter

        self.__set_if_idx()

    def __open_adapater(self, name: str):
        rs = self.__wintun.WintunOpenAdapter(name)
        return rs

    def close_adapter(self):
        if not self.__adapter: return

        self.__wintun.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        self.__wintun.WintunCloseAdapter(self.__adapter)

    def delete_driver(self):
        self.__wintun.WintunDeleteDriver()

    def get_running_driver_version(self):
        self.__wintun.WintunGetRunningDriverVersion.argtypes = []
        self.__wintun.WintunGetRunningDriverVersion.restype = wintypes.DWORD

        return self.__wintun.WintunGetRunningDriverVersion()

    def start_session(self):
        self.__wintun.WintunStartSession.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.__wintun.WintunStartSession.restype = ctypes.c_void_p
        self.__session = self.__wintun.WintunStartSession(self.__adapter, 0x400000)

    def end_session(self):
        if not self.__session: return

        self.__wintun.WintunEndSession.argtypes = [ctypes.c_void_p]
        self.__wintun.WintunEndSession(self.__session)

    def readable(self):
        if ctypes.windll.kernel32.GetLastError() != 259: return True
        return False

    def wait_read_event(self, misc_timeout: int):
        self.__wintun.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        self.__wintun.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        # ERROR_NO_MORE_ITEMS
        if ctypes.windll.kernel32.GetLastError() != 259: return

        handle = self.__wintun.WintunGetReadWaitEvent(self.__session)

        ctypes.windll.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        ctypes.windll.kernel32.WaitForSingleObject(handle, misc_timeout)

    def read(self):
        self.__wintun.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.__wintun.WintunReceivePacket.restype = ctypes.c_void_p
        capacity = wintypes.DWORD()

        packet_ptr = self.__wintun.WintunReceivePacket(self.__session, ctypes.byref(capacity))

        if packet_ptr:
            buf = ctypes.create_string_buffer(capacity.value)
            ctypes.memmove(buf, packet_ptr, capacity.value)

            self.__wintun.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            self.__wintun.WintunReleaseReceivePacket(self.__session, packet_ptr)

            return buf.raw

        return b""

    def write(self, byte_data: bytes):
        size = len(byte_data)

        self.__wintun.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.__wintun.WintunAllocateSendPacket.restype = ctypes.c_void_p

        buffer = self.__wintun.WintunAllocateSendPacket(self.__session, size)

        ctypes.memmove(buffer, byte_data, size)

        self.__wintun.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.__wintun.WintunSendPacket(self.__session, buffer)

    def set_ip(self, ip: str, prefix: int, dnsserver=None, is_ipv6=False):
        cmds = []
        if is_ipv6:
            self.__my_ipv6 = ip
            cmds.append(
                "netsh interface ipv6 add address \"%s\" %s/%s" % (self.__nic_name, ip, prefix)
            )
            if dnsserver:
                cmds.append(
                    "netsh interface ipv6 set dnsservers \"%s\" static %s primary validate=no" % (
                        self.__nic_name, dnsserver)
                )
            ''''''
        else:
            self.__my_ipv4 = ip
            netmask = netutils.ip_prefix_convert(prefix, is_ipv6=False)
            cmds.append("netsh interface ipv4 set address \"%s\" static %s %s" % (self.__nic_name, ip, netmask))
            if dnsserver:
                cmds.append(
                    "netsh interface ipv4 set dns \"%s\" static %s primary validate=no" % (self.__nic_name, dnsserver))
            ''''''
        for cmd in cmds:
            self.__exe_cmd(cmd)

    def create_route(self, network: str, prefix: int, is_ipv6=False, metric=1):
        if is_ipv6 and self.__my_ipv6 is None:
            return
        if not is_ipv6 and self.__my_ipv4 is None:
            return

        if is_ipv6:
            cmd = "route -6 add %s/%s %s metric %s if %s" % (
                network, prefix, self.__my_ipv6, metric, self.__if_idx)
        else:
            mask = netutils.ip_prefix_convert(prefix, is_ipv6=False)
            cmd = "route add %s mask %s %s metric %s if %s" % (network, mask, self.__my_ipv4, metric, self.__if_idx)

        self.__exe_cmd(cmd)

    def delete_route(self, network: str, prefix: int, is_ipv6=False):
        if is_ipv6 and self.__my_ipv6 is None:
            return
        if not is_ipv6 and self.__my_ipv4 is None:
            return
        if is_ipv6:
            cmd = "route delete %s/%s if %s" % (
                network, prefix, self.__if_idx)
        else:
            mask = netutils.ip_prefix_convert(prefix, is_ipv6=False)
            cmd = "route delete %s mask %s if %s" % (network, mask, self.__if_idx)
        self.__exe_cmd(cmd)

    def __get_all_nic_without_self(self, self_name: str):
        fdst = os.popen("netsh int ipv4 show interfaces")
        bf = fdst.buffer.read()
        try:
            s = bf.decode("utf-8")
        except UnicodeDecodeError:
            s = bf.decode("gbk")
        fdst.close()
        _list = s.split("\n")
        _list2 = []

        for s in _list:
            s = s.replace("\r", "")
            if not s: continue
            _list2.append(s)

        if len(_list2) <= 2: return []
        _list2 = _list2[2:]
        results = []
        for line in _list2:
            line = line.strip()
            p = line.find(" ")
            idx = line[0:p]
            p = p + 1
            line = line[p:].strip()
            p = line.find(" ")
            metric = line[0:p]
            p = p + 1
            line = line[p:].strip()
            p = line.find(" ")
            mtu = line[0:p]
            p = p + 1
            line = line[p:].strip()
            p = line.find(" ")
            status = line[0:p]
            name = line[p:].strip()

            if name.lower().find("loopback") >= 0: continue
            if name.lower().find("vethernet") >= 0: continue
            if name.lower().find("vmware") >= 0: continue
            if name.lower().find(self_name) >= 0: continue
            results.append((int(idx), int(metric), int(mtu), status, name))

        return results

    def __parse_show_dns_cmd(self, s: str):
        """解析show DNS命令
        """
        # print(s)
        nameservers = []
        s = s.strip()
        _list = s.split("\n")
        _list2 = []
        for line in _list:
            line = line.replace("\r", "").strip()
            if not line: continue
            _list2.append(line)

        # if len(_list2) > 3:
        #    nameservers.append(_list2[2])
        s = _list2[1]
        p = s.find(":")
        p += 1
        s = s[p:].strip()
        if netutils.is_ipv4_address(s) or netutils.is_ipv6_address(s):
            nameservers.append(s)
        if len(_list2) == 4:
            nameservers.append(_list2[2])

        return nameservers

    def get_nic_nameservers(self, nic_name: str, is_ipv6=False):
        if not is_ipv6:
            fdst = os.popen("netsh interface ipv4 show dns \"%s\"" % nic_name)
        else:
            fdst = os.popen("netsh interface ipv6 show dns \"%s\"" % nic_name)
        bf = fdst.buffer.read()
        try:
            s = bf.decode("utf-8")
        except UnicodeDecodeError:
            s = bf.decode("gbk")
        fdst.close()
        nameservers = self.__parse_show_dns_cmd(s)

        return nameservers

    def set_nic_dns_and_not_self(self, dnsserver=None, is_ipv6=False):
        """自动设置除自身之外的其他网卡DNS
        """
        # 修改所有网卡为VPN的DNS,避免泄露DNS
        nics = self.__get_all_nic_without_self(self.__nic_name)
        cmds = []
        for nic in nics:
            if nic[3] != "connected": continue
            nameservers = self.get_nic_nameservers(nic[4], is_ipv6=False)
            if not nameservers: continue
            # print(nameservers)
            # 网卡存在DNS的,那么清除DNS
            if is_ipv6:
                cmd = """netsh interface ipv6 delete dnsservers "%s" all""" % (nic[4])
                cmds.append(cmd)
                if dnsserver:
                    cmds.append(
                        "netsh interface ipv6 set dnsservers \"%s\" static %s primary validate=no" % (nic[4],
                                                                                                      dnsserver))
                    ''''''
                ''''''
            else:
                cmd = """netsh interface ipv4 delete dnsservers "%s" all""" % (nic[4])
                cmds.append(cmd)
                if dnsserver: cmds.append(
                    "netsh interface ipv4 set dns \"%s\" static %s primary validate=no" % (nic[4], dnsserver))
                ''''''
            ''''''
        for cmd in cmds: self.__exe_cmd(cmd)

    def is_chaned_for_nic_dnsserver(self):
        """检查系统网卡是否发生改变
        """
        nics = self.__get_all_nic_without_self(self.__nic_name)
        nameservers = []
        for nic in nics:
            nameservers_a = self.get_nic_nameservers(nic[4], is_ipv6=False)
            nameservers_b = self.get_nic_nameservers(nic[4], is_ipv6=True)
            if nameservers_a:
                nameservers += nameservers_a
            if nameservers_b:
                nameservers += nameservers_b
            ''''''
        s = "".join(nameservers)
        md5 = hashlib.md5()
        md5.update(s.encode("utf-8"))
        v = md5.digest()
        if v != self.__os_nic_md5:
            self.__os_nic_md5 = v
            return True
        return False

# get_all_nic_without_self("fdslight")
# wintun = Wintun("../../drivers/wintun/amd64/wintun.dll")
# wintun.create_adapater("fdslight", "fdslight")
# wintun.start_session()
# wintun.set_ip("10.1.1.1", 0, dnsserver="223.5.5.5")
# while 1:
#    rs = wintun.read()
#    if rs:
#        wintun.write(rs)
#    wintun.wait_read_event(10000)
# wintun.set_nic_dns_and_not_self()
