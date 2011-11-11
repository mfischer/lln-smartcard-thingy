#!/usr/bin/env python2
import sys

from smartutils import SmartUtils
from smartcard.util import toHexString, toBytes
from desfire import challenge
from binascii import hexlify, unhexlify

def main ():
    s = SmartUtils ()
    s.poll ()
    s.selectApplication (aid=0)
    s.auth (key=16*"00")
    s.eraseAll ()
    s.createApplication (aid=1)
    s.createApplication (aid=2)
    s.selectApplication (aid=1)
    sk = s.auth (key=16*"00")
    print 'SessionKey is:', hexlify(sk)
    s.changeKey(0, 16*"11", hexlify(sk), False, 8*"00")
    #def changeKey (self, keyNo, newKey, currentSessionKey, authKeyDifferent = True, currentKey = None):
    s.selectApplication (aid=2)
    s.auth (key=16*"00")

if __name__ == "__main__":
    try:
        main ()
    except KeyboardInterrupt:
        pass
    
