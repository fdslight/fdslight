#!/usr/bin/env python3

import time
import pywind.lib.timer as timer

A_RECORD = 0
AAAA_RECORD = 1


class DNSCache(object):
    __cache_timeout = None
    __timer = None
    __A_records = None
    __AAAA_records = None

    def __init__(self):
        self.__timer = timer.timer()
        self.__A_records = {}
        self.__AAAA_records = {}
        # 默认缓存超时时间,单位秒
        self.__cache_timeout = 120

    def set_timeout(self, seconds: int):
        # 设置最低阀值
        if seconds < 30:
            return False
        # 设置最大阀值
        if seconds > 86400:
            return False
        self.__cache_timeout = seconds
        return True

    def set_cache_record(self, name: str, address: str, _type=A_RECORD):
        # 过滤记录类型
        if _type not in (A_RECORD, AAAA_RECORD,):
            return False
        if not name: return False
        if not address: return False

        now = time.time()

        if _type == A_RECORD:
            obj = self.__A_records
            new_name = "A_" + name
        else:
            obj = self.__AAAA_records
            new_name = "AAAA_" + name

        obj[name] = {"time": now, "address": address}
        self.__timer.set_timeout(new_name, 10)

        return True

    def clear_all_records(self):
        # 清除所有记录
        self.__A_records = {}
        self.__AAAA_records = {}

    def cache_loop(self):
        names = self.__timer.get_timeout_names()
        dels_a = []
        dels_aaaa = []
        now = time.time()

        for name in names:
            p = name.find("_")
            if p <= 0: continue
            r_type = name[:p]
            if r_type not in ("A", "AAAA",): continue
            if r_type == "A":
                records = self.__A_records
            else:
                records = self.__AAAA_records
            p += 1
            new_name = name[p:]
            if new_name not in records: continue
            r = records[new_name]
            if now - r['time'] >= self.__cache_timeout:
                if r_type == 'A':
                    dels_a.append(new_name)
                else:
                    dels_aaaa.append(new_name)
                ''''''
            else:
                self.__timer.set_timeout(name, 10)
            ''''''
        for k in dels_a:
            del self.__A_records[k]
        for k in dels_aaaa:
            del self.__AAAA_records[k]

    def print_records(self):
        print("A records:", self.__A_records)
        print("AAAA records:", self.__AAAA_records)

    def record_get(self, name: str, _type=A_RECORD):
        if _type == A_RECORD:
            records = self.__A_records
        else:
            records = self.__AAAA_records

        return records.get(name, None)


"""
cls = DNSCache()
cls.set_timeout(30)
cls.set_cache_record("mytest.com", "192.168.1.1")
cls.print_records()

for i in range(4):
    time.sleep(11)
    cls.cache_loop()
cls.print_records()
"""
