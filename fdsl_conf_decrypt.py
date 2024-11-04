#!/usr/bin/env python3
# 配置解密工具
import os, sys

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.file_sec as file_sec


def main():
    d = input("please set encrypt diretory:")

    if not os.path.isdir(d):
        print("ERROR:%s is not a directory" % d)
        return

    key = input("please set key:")
    if not key:
        print("ERROR:key cannot is empty")
        return

    print()
    _list = os.listdir(d)
    for name in _list:
        fpath = "%s/%s" % (d, name)
        if not os.path.isfile(fpath): continue
        _list = name.split(".")
        # 跳过带sec的后缀
        x = _list.pop()
        if x.lower() != "sec": continue
        dst_path = d + "/" + ".".join(_list)
        file_sec.decrypt_file(fpath, dst_path, key, is_deleted_src_file=True)
        print("NOTE:decrypt file %s OK" % fpath)
    print()
    print("decrypt done")


if __name__ == '__main__': main()
