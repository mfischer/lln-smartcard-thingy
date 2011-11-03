#!/usr/bin/env python2

import pyDes
import os
from binascii import hexlify, unhexlify

def generateResponse (nonce, debug=False):
    nt = decipher(nonce)
    nt2 = nt[1:]+nt[:1]
    nr = os.urandom(8)

    nr = unhexlify ('1122334455667788')
    d1 = decipher (nr)
    buff = hex (int (hexlify (d1), 16) ^ int (hexlify (nt2), 16))
    d2 = decipher (unhexlify (buff[2:-1]))

    if debug:
        print 'nt =', hexlify (nt)
        print 'nt2 =', hexlify (nt2)
        print 'D1 = ', hexlify (d1)
        print 'Buff =', buff[2:-1]
        print 'D2 = ', hexlify(d2)
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

if __name__ == '__main__':
    nonce  = 0x6e7577944adffc0c
    _nonce = unhexlify (hex (nonce)[2:])
    response, nr = generateResponse (_nonce)
    print 'Response = ', hexlify (response)
    print 'Nonce = ', hexlify (nr)
    print 'Verification ok?', verifyResponse ('AD6CC16025CCFB7B', nr)