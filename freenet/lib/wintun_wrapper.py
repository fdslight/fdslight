#!/usr/bin/env python3

import ctypes, os
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

    def __init__(self, dll_path: str):
        self.__wintun = ctypes.CDLL(dll_path)

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
                    "netsh interface ipv6 set dnsservers \"%s\" static %s primary validate=no" % (self.__nic_name, dnsserver)
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
            print(cmd)
            os.system(cmd)

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

        os.system(cmd)

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
        print(cmd)
        os.system(cmd)

# wintun = Wintun("bin/amd64/wintun.dll")
# wintun.create_adapater("fdslight", "fdslight")
# wintun.start_session()
# wintun.set_ip("10.1.1.1", 0, dnsserver="223.5.5.5")
# while 1:
#    rs = wintun.read()
#    if rs:
#        wintun.write(rs)
#    wintun.wait_read_event(10000)
