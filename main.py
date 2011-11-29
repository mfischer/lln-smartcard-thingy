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
    sk = s.auth (key=16*"00")
    print 'SessionKey is:', hexlify(sk)
    s.eraseAll ()
    s.createApplication (aid=1)
    #s.createApplication (aid=2)
    s.selectApplication (aid=1)
    sk = s.auth (key=16*"00",key_num=0))
    print 'SessionKey is:', hexlify(sk)
    s.changeKey(0, 8*"11"+8*"00", hexlify(sk), False, 8*"00")
    sk = s.auth (key=8*"11"+8*"00",key_num=0)
    
    s.createApplication (aid=2)
    s.selectApplication (aid=2)
    s.auth (key=16*"00")
    s.createStdDataFile (fileNo = 0x01, comSet = 0x03, accRights = [0xE0, 0x00], fileSizeLSB = [0x20, 0x00, 0x00])
    s.deleteStdDataFile (fileNo = 0x01)

if __name__ == "__main__":
    try:
        main ()
    except KeyboardInterrupt:
        pass
    
