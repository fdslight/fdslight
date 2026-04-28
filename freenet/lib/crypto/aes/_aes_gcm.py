#!/usr/bin/env python3
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("please install cryptography module")
    sys.exit(-1)


def encrypt(key, none, aad, byte_data):
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.encrypt(none, byte_data, aad)
    except:
        return None
    return data


def decrypt(key, none, aad, byte_data):
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(none, byte_data, aad)
    except:
        return None

    return data


def get_size(byte_size):
    return 16 + byte_size
