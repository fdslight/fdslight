#!/usr/bin/env python3

import hashlib, json, random, os

# 表示IP数据
ACT_IPDATA = 1
# 表示DNS数据
ACT_DNS = 2

# PING
ACT_PING = 3
# PONG
ACT_PONG = 4

# ZLIB压缩的IP报文
ACT_ZLIB_IPDATA = 5
# ZLIB压缩的DNS报文
ACT_ZLIB_DNS = 6

ACTS = (ACT_IPDATA, ACT_DNS, ACT_PING, ACT_PONG,
        ACT_ZLIB_IPDATA, ACT_ZLIB_DNS,
        )


def rand_bytes(max_size=64):
    return os.urandom(random.randint(1, max_size))


class ProtoError(Exception): pass


def gen_session_id(user_name, passwd):
    """生成会话ID"""
    sts = "%s%s" % (user_name, passwd)

    return calc_content_md5(sts.encode("utf-8"))


def calc_content_md5(content):
    md5 = hashlib.md5()
    md5.update(content)

    return md5.digest()


def load_crypto_configfile(fpath):
    """载入加密配置文件
    :param fpath:
    :return:
    """
    with open(fpath, "r") as f:
        data = f.read()

    return json.loads(data)
