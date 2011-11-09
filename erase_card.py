#!/usr/bin/env python2
import sys

from smartutils import SmartUtils
from smartcard.util import toHexString, toBytes

def main ():
    s = SmartUtils()
    s.poll()
    s.auth()
    s.eraseAll()

if __name__ == "__main__":
    try:
        main ()
    except KeyboardInterrupt:
        pass
