#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = b"a"
aad = b"ddd"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
print(len(ct))
msg=aesgcm.decrypt(nonce, ct, aad)
print(msg)