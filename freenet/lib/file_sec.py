#!/usr/bin/env python3
# 文件加解密

import os, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(src_path: str, dst_path: str, key: str, is_deleted_src_file=False):
    fdst = open(src_path, 'rb')
    src_data = fdst.read()
    fdst.close()

    file_md5 = hashlib.md5(src_data).digest()
    nonce = file_md5
    byte_key = hashlib.md5(key.encode('utf-8')).digest()
    aad = file_md5

    aesgcm = AESGCM(byte_key)
    ct = aesgcm.encrypt(nonce, src_data, aad)

    fdst = open(dst_path, 'wb')
    fdst.write(file_md5 + ct)
    fdst.close()

    if is_deleted_src_file: os.remove(src_path)


def decrypt_file(src_path: str, dst_path: str, key: str, is_deleted_src_file=False):
    fdst = open(src_path, 'rb')
    src_data = fdst.read()
    fdst.close()

    file_md5 = src_data[0:16]
    src_data = src_data[16:]
    byte_key = hashlib.md5(key.encode('utf-8')).digest()

    nonce = file_md5
    aad = file_md5

    aesgcm = AESGCM(byte_key)
    rs = aesgcm.decrypt(nonce, src_data, aad)

    if hashlib.md5(rs).digest() != file_md5:
        return False

    with open(dst_path, 'wb') as f:
        f.write(rs)
    f.close()

    if is_deleted_src_file: os.remove(src_path)

    return True


def decypt_file_no_gen_file(path: str, key: str):
    fdst = open(path, 'rb')
    src_data = fdst.read()
    fdst.close()

    file_md5 = src_data[0:16]
    src_data = src_data[16:]
    nonce = file_md5
    aad = file_md5
    byte_key = hashlib.md5(key.encode('utf-8')).digest()
    aesgcm = AESGCM(byte_key)
    rs = aesgcm.decrypt(nonce, src_data, aad)

    if hashlib.md5(rs).digest() != file_md5:
        print("ERROR:cannot decrypt file %s" % path)
        return b""

    return rs
