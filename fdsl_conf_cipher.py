#!/usr/bin/env python3
# 配置加密工具
import os, sys, getpass

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.file_sec as file_sec


def main():
    helper_doc = "helper:encrypt or decrypt"
    if len(sys.argv) != 2:
        print(helper_doc)
        return

    if sys.argv[1] not in ("encrypt", "decrypt",):
        print(helper_doc)
        return

    action = sys.argv[1]

    d = input("please set encrypt diretory:")

    if not os.path.isdir(d):
        print("ERROR:%s is not a directory" % d)
        return

    key = getpass.getpass("please set security key:")
    if not key:
        print("ERROR:key cannot is empty")
        return

    if action == "encrypt":
        key2 = getpass.getpass("sure your key again:")
        if key2 != key:
            print("ERROR:different key, please try again")
            return
        ''''''
    print()
    _list = os.listdir(d)
    for name in _list:
        fpath = "%s/%s" % (d, name)
        if not os.path.isfile(fpath): continue
        _list = name.split(".")

        x = _list.pop()
        if action == "encrypt":
            if x.lower() == "sec": continue
            file_sec.encrypt_file(fpath, fpath + ".sec", key, is_deleted_src_file=True)
            print("NOTE:encrypt file %s OK" % fpath)
        else:
            if x.lower() != "sec": continue
            dst_path = d + "/" + ".".join(_list)
            ok = file_sec.decrypt_file(fpath, dst_path, key, is_deleted_src_file=True)
            if ok:
                print("NOTE:decrypt file %s OK" % fpath)
            else:
                print("ERROR:decrypt file %s fail" % fpath)
        ''''''
    ''''''


if __name__ == '__main__': main()
