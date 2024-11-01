#!/usr/bin/env python3

import ctypes, os
import ctypes.wintypes as wintypes


class Wintun(object):
    __wintun = None
    __adapter = None
    __session = None
    __nic_name = None
    __my_ipv4 = None
    __my_ipv6 = None

    def __init__(self, dll_path: str):
        self.__wintun = ctypes.CDLL(dll_path)

    def create_adapater(self, name: str, tunnel_type: str):
        self.__adapter = self.__open_adapater(name)
        self.__nic_name = name
        if not self.__adapter:
            self.__wintun.WintunCreateAdapter.restype = ctypes.c_void_p
            adapter = self.__wintun.WintunCreateAdapter(name, tunnel_type, None)
            self.__adapter = adapter
        return

    def __open_adapater(self, name: str):
        rs = self.__wintun.WintunOpenAdapter(name)
        return rs

    def close_adapter(self):
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
        self.__session = self.__wintun.WintunStartSession(self.__adapter, 0x20000)

    def end_session(self):
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
        self.__wintun.WintunReceivePacket.restype = ctypes.c_char_p
        capacity = wintypes.DWORD()

        packet_ptr = self.__wintun.WintunReceivePacket(self.__session, ctypes.byref(capacity))

        if packet_ptr:
            packet = ctypes.string_at(packet_ptr, capacity.value)

            self.__wintun.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self.__wintun.WintunReleaseReceivePacket(self.__session, packet_ptr)

            return packet

        return b""

    def write(self, byte_data: bytes):
        size = len(byte_data)

        self.__wintun.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self.__wintun.WintunAllocateSendPacket.restype = ctypes.c_char_p

        buffer = self.__wintun.WintunAllocateSendPacket(self.__session, size)

        self.__wintun.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.__wintun.WintunSendPacket(self.__session, buffer)

    def set_ip(self, ip: str, prefix: int, dnsserver=None, is_ipv6=False):
        cmds = []
        if is_ipv6:
            self.__my_ipv6 = ip
        else:
            self.__my_ipv4 = ip
            cmds.append("netsh interface ipv4 set address \"%s\" static %s 255.255.255.0" % (self.__nic_name, ip))
            if dnsserver:
                cmds.append("netsh interface ipv4 set dns \"%s\" static %s" % (self.__nic_name, dnsserver))
            ''''''
        for cmd in cmds:
            os.system(cmd)

    def create_route(self, network: str, prefix: int, is_ipv6=False):
        if is_ipv6 and self.__my_ipv6 is None:
            return
        if not is_ipv6 and self.__my_ipv4 is None:
            return
        if is_ipv6:
            cmd = ""
        else:
            cmd = "route add %s mask %s %s" % (network, prefix, self.__my_ipv4)

        os.system(cmd)

    def delete_route(self, network: str, prefix: int, is_ipv6=False):
        if is_ipv6 and self.__my_ipv6 is None:
            return
        if not is_ipv6 and self.__my_ipv4 is None:
            return
        if is_ipv6:
            cmd = ""
        else:
            cmd = "route delete %s mask %s %s" % (network, prefix, self.__my_ipv4)
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
