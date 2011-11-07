#!/usr/bin/env python2
import sys

from smartutils import SmartUtils
from smartcard.util import toHexString, toBytes

def main ():
    s = SmartUtils ()
    s.poll ()
    s.auth (key=16*"00")
    s.eraseAll ()
    s.createApplication (aid=1)
    s.createApplication (aid=2)
    s.selectApplication (aid=1)
    s.selectApplication (aid=2)

if __name__ == "__main__":
    try:
        main ()
    except KeyboardInterrupt:
        pass
    
