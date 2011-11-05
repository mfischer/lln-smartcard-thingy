#!/usr/bin/env python2

import binascii

def _updateCrc (crc, inp):
    inp = inp ^ (crc & 0x00ff)
    inp = inp ^ (inp << 4) & 0x00ff
    return (crc >> 8) ^ (inp << 8) ^ (inp << 3) ^ (inp >> 4)

def _flipBytes (val):
    return ((0xff00 & val) >> 8) |  ((0x00ff & val) << 8)

def _calculateCrc (vals, init):
    return reduce (_updateCrc, vals, init)

def _calculateFlippedCrc (vals, init):
    return _flipBytes (reduce (_updateCrc, vals, init))

def mergeList (list):
    def f (elem):
        if elem < 0x10:
            return '0' + hex(elem)[2:]
        else:
            return hex(elem)[2:]

    result = ''.join(map (f ,list))
    return result

def _listFromStr (str):
    assert not len(str) % 2, 'len(str) is not even'
    tmp = ""
    l = list()
    for b in str:
        if len(tmp):
            l.append(tmp+b)
            tmp = ""
        else:
            tmp = b
    return map ((lambda e: int (e, 16)), l)

def calculateCrc (string, init = 0x6363):
    return _calculateCrc (_listFromStr (string), init)

def calculateFlippedCrc (string, init = 0x6363):
    return _calculateFlippedCrc (_listFromStr (string), init)



if __name__ == '__main__':
    foo = "11223344556677889900aabbccddeeff"
    try:
        print hex (calculateFlippedCrc (foo))
    except KeyboardInterrupt:
        pass
