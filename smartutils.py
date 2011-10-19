#!/usr/bin/env python2
import smartcard

from smartcard.util import toHexString, toBytes

class SmartUtils:
    def __init__(self):
        self.session = None
        if len(smartcard.listReaders()) == 0:
            print("No reader found")
        else:
            self.session = smartcard.Session()
            print("Reader selected")
    
    def poll(self):
        data, sw1, sw2 = self.session.sendCommandAPDU([0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x02, 00])
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes ("FF C0 00 00 " + hex(sw2)[2:]))
        if sw1 == 0x90 and sw2 == 0x00:
            print("OK: "+toHexString(data))
        else:
            print("Error: "+toHexString(data)+" "+toHexString([sw1, sw2]))


if __name__ == "__main__":
    s = SmartUtils()
    s.poll()
