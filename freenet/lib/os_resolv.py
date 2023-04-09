#!/usr/bin/env python3
"""处理操作系统的resolv.conf文件
"""
import os


class resolv(object):
    __path = None

    def __init__(self, path="/etc/resolv.conf"):
        self.__path = path

    def __str_to_list_by_space(self, s: str):
        """通过空格分割字符串
        :param s:
        :return:
        """
        _list = s.split(" ")
        results = []
        for x in _list:
            if not x: continue
            results.append(x)

        return results

    def get_os_resolv(self):
        """获取操作系统nameserver服务器信息
        :return:
        """
        fpath = self.__path
        _list = []

        # 文件不存在首先创建一个空文件
        if not os.path.isfile(fpath):
            fdst = open(fpath, "w")
            fdst.close()

        fdst = open(fpath, "r")
        for line in fdst:
            line = line.strip()
            line = line.replace("\n", "")
            line = line.replace("\r", "")
            if not line: continue
            # 取出注释行
            if line[0] == "#": continue
            _list.append(tuple(self.__str_to_list_by_space(line)))

        return _list

    def exists(self, nameserver: str):
        """检查nameserver是否已经存在
        :param nameserver:
        :return:
        """
        _list = self.get_os_resolv()
        exists = False
        for info in _list:
            if len(info) != 2: continue
            if info[0] != "nameserver": continue
            if info[1] == nameserver:
                exists = True
                break
            ''''''
        return exists

    def write_to_file(self, seq: list):
        """写入到系统文件中
        :param seq: 格式为[("nameserver",server_address),...]
        :return:
        """
        fd = open(self.__path, "w")
        for t in seq:
            line = " ".join(t)
            fd.write(line)
            fd.write("\n")
        fd.close()
