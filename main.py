#!/usr/bin/env python2
import sys

from smartutils import SmartUtils
from smartcard.util import toHexString, toBytes

def getNonce():
    
    print("Enter an authentification nonce or <Enter> for default value.\nThe nonce should be 8 bytes-long in hexadecimal\nDefault: 11 22 33 44 55 66 77 88.")
    
    is_nonce = False
    while True:
        nonce = raw_input("Nonce: ")
        if len(nonce) == 0:
            # use default
            return toBytes("11 22 33 44 55 66 77 88")
        else:
            if checkNonce(nonce):
                return toBytes(nonce)

def checkNonce(nonce):
    try:
        n = toBytes(nonce)
        if len(n)==8:
            # is hex and 8 bytes
            return True
    except:
        pass
    
    print(nonce+" is not valid")   
    return False


if __name__ == "__main__":
    s = SmartUtils()
    nonce = getNonce()
    s.poll()
    s.auth(nonce)
