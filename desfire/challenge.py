#!/usr/bin/env python2

import pyDes
import os
from binascii import hexlify, unhexlify

def generateResponse (nonce, our_nonce = None, debug=False):
    nt = decipher(nonce)
    nt2 = nt[1:]+nt[:1]
    nr = our_nonce or os.urandom(8)
    d1 = decipher (nr)
    buff = int (hexlify (d1), 16) ^ int (hexlify (nt2), 16)
    buff = buff & 0xffffffffffffff00 >> 8 | buff & 0x00000000000000ff << 56
    d2 = decipher (unhexlify(hex (buff)[2:-1]))

    if debug:
        print 'nt =', hexlify (nt)
        print 'nt2 =', hexlify (nt2)
        print 'D1 =', hexlify (d1)
        print 'Buff =', hex(buff)[2:-1]
        print 'D2 =', hexlify(d2)
        print 'D1 || D2 =',  hexlify (d1) + hexlify (d2)

    return (d1 + d2, nr)

def decipher (data, key = 8*'00', iv=8*'00', pad=None, mode=pyDes.CBC):
    _key = unhexlify (key)
    _iv  = unhexlify (iv)
    des_box=pyDes.des (_key, mode, pad=pad, padmode=pyDes.PAD_NORMAL)
    des_box.setIV (_iv)
    return des_box.decrypt (data)

def verifyResponse (resp, nr):
    _resp = unhexlify (resp)
    nr2 = nr[1:]+nr[:1]
    return decipher (_resp) == nr2

def deriveSessionKey (nonce, ourNonce, isPalindrome=False):
    if isPalindrome:
        sessionKey = ourNonce[:4] + nonce[:4]
        assert len(sessionKey) is 8
        return sessionKey
    else:
        sessionKey = ourNonce[:4] + nonce[:4] + ourNonce[4:] + nonce[4:]
        assert len(sessionKey) is 16
        return sessionKey

def isPalindrome (key):
    return key == key[::-1]

if __name__ == '__main__':
    nonce  = 0x6e7577944adffc0c
    _nonce = unhexlify (hex (nonce)[2:])
    our_nonce = 0x1122334455667788
    _our_nonce = unhexlify (hex (our_nonce)[2:])
    response, nr = generateResponse (_nonce, _our_nonce)
    print 'Response = ', hexlify (response)
    print 'Nonce = ', hexlify (nr)
    print 'Verification ok?', verifyResponse ('AD6CC16025CCFB7B', nr)
    print 'Session key = ', hexlify (deriveSessionKey (_nonce, _our_nonce))
