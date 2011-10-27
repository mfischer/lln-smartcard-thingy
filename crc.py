#!/usr/bin/env python2

def updateCrc (crc, inp):
    inp = inp ^ (crc & 0x00ff)
    inp = inp ^ (inp << 4) & 0x00ff
    return (crc >> 8) ^ (inp << 8) ^ (inp << 3) ^ (inp >> 4)

def flipBytes (val):
    return ((0xff00 & val) >> 8) |  ((0x00ff & val) << 8)

def calculateCrc (vals, init):
    return reduce (updateCrc, vals, init)

def calculateFlippedCrc (vals, init):
    return flipBytes (reduce (updateCrc, vals, init))

if __name__ == '__main__':
    foo = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    try:
        print hex (calculateFlippedCrc(foo, 0x6363))
    except KeyboardInterrupt:
        pass
