#!/usr/bin/env python3
# 文件加解密

import os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_file(src_path: str, dst_path: str, key: str, is_deleted_src_file=False):
    fdst = open(src_path, 'rb')
    src_data = fdst.read()
    fdst.close()
    byte_key = hashlib.md5(key.encode('utf-8')).digest()
    key2 = key + key
    iv = hashlib.md5(key2.encode("utf-8")).digest()

    cipher = Cipher(algorithms.AES(byte_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    with open(dst_path, 'wb') as f:
        f.write(encryptor.update(src_data))
    encryptor.finalize()
    f.close()

    if is_deleted_src_file: os.remove(src_path)


def decrypt_file(src_path: str, dst_path: str, key: str, is_deleted_src_file=False):
    fdst = open(src_path, 'rb')
    src_data = fdst.read()
    fdst.close()
    byte_key = hashlib.md5(key.encode('utf-8')).digest()
    key2 = key + key
    iv = hashlib.md5(key2.encode("utf-8")).digest()

    cipher = Cipher(algorithms.AES(byte_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    with open(dst_path, 'wb') as f:
        f.write(decryptor.update(src_data))
    decryptor.finalize()
    f.close()

    if is_deleted_src_file: os.remove(src_path)


def decypt_file_no_gen_file(path: str, key: str):
    fdst = open(path, 'rb')
    src_data = fdst.read()
    fdst.close()
    byte_key = hashlib.md5(key.encode('utf-8')).digest()
    key2 = key + key
    iv = hashlib.md5(key2.encode("utf-8")).digest()

    cipher = Cipher(algorithms.AES(byte_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    rdata = decryptor.update(src_data)
    decryptor.finalize()

    return rdata
