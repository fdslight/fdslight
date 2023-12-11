#!/usr/bin/env python3

import freenet.lib.racs_cext as racs_cext

s = bytes(200)

racs_cext.modify_ip_address_from_netpkt(s,b"ssss",True,False)

print(s)