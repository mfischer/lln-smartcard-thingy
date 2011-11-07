#!/usr/bin/env python2

#import pyDes
import os
from binascii import hexlify as _hexlify
from binascii import unhexlify as _unhexlify

import M2Crypto.EVP
import cStringIO

def generateResponse (nonce, key=16*'00', ourNonce = None, debug=False):
    """
    Given a nonce picked by the verifier computes the response of the prover.

    nonce      -- the nonce as given by the verifier.
    our_nonce  -- the nonce of the prover (in case he choses one).
    debug      -- output the intermediate steps.
    """
    nt = _decipher(nonce, key)
    nt2 = nt[1:]+nt[:1]
    nr = ourNonce or os.urandom(8)
    d1 = _decipher (nr, key)
    buff = int (_hexlify (d1), 16) ^ int (_hexlify (nt2), 16)
    buff = buff & 0xffffffffffffff00 >> 8 | buff & 0x00000000000000ff << 56
    d2 = _decipher (_unhexlify(hex (buff)[2:-1]), key)

    if debug:
        print 'nt =', _hexlify (nt)
        print 'nt2 =', _hexlify (nt2)
        print 'D1 =', _hexlify (d1)
        print 'Buff =', hex(buff)[2:-1]
        print 'D2 =', _hexlify(d2)
        print 'D1 || D2 =',  _hexlify (d1) + _hexlify (d2)

    return (d1 + d2, nr)

#def _decipherPyDes (data, key = 8*'00', iv=8*'00', pad=None, mode=pyDes.CBC):
    #_key = _unhexlify (key)
    #_iv  = _unhexlify (iv)
    #des_box=pyDes.des (_key, mode, pad=pad, padmode=pyDes.PAD_NORMAL)
    #des_box.setIV (_iv)
    #return des_box.decrypt (data)

def _cipher_filter(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
           break
        outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue() 

def _decipher (data, key = 16*'00', iv=8*'00', pad=None):
    _key = _unhexlify (key)
    _iv  = _unhexlify (iv)
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(data)

    if pad is None:
        _pad = 0
    else:
        _pad = 1

    des_box=M2Crypto.EVP.Cipher (alg='des_ede_cbc',
                                 op=0, key=_key,
                                 iv=_iv,
                                 padding = _pad)
    plaintext =_cipher_filter(des_box, cbuf, pbuf)
    pbuf.close ()
    cbuf.close ()
    return plaintext

def verifyResponse (resp, nr, key = 16*'00'):
    """
    Verifies the resonse given by the verifier for mutual authentication.

    resp    -- the response as given by the verifier.
    nonce   -- the nonce as chosen by the prover.
    """

    _resp = _unhexlify (resp)
    nr2 = nr[1:]+nr[:1]
    return _decipher (_resp, key) == nr2

def deriveSessionKey (nonce, ourNonce, isDES=False):
    """
    Derives the session key for the DESfire.

    nonce    -- the nonce as given by the verifier.
    ourNonce -- the nonce as chosen by the prover.
    isDes    -- for the special case of TDES where k1 = k2 (DES).
    """

    if isDES:
        sessionKey = ourNonce[:4] + nonce[:4]
        assert len(sessionKey) is 8
        return sessionKey
    else:
        sessionKey = ourNonce[:4] + nonce[:4] + ourNonce[4:] + nonce[4:]
        assert len(sessionKey) is 16
        return sessionKey

def isDES (key):
    """
    Returns True if a given 3DES key is used to actually do DES.
    """

    h = len (key) / 2
    return key[:h] == key[h:]

if __name__ == '__main__':
    nonce  = 0x6e7577944adffc0c
    _nonce = _unhexlify (hex (nonce)[2:])
    ourNonce = 0x1122334455667788
    _ourNonce = _unhexlify (hex (ourNonce)[2:])
    response, nr = generateResponse (_nonce, ourNonce = _ourNonce, debug=True)
    print 'Response = ', _hexlify (response)
    print 'Nonce = ', _hexlify (nr)
    print 'Verification ok?', verifyResponse ('AD6CC16025CCFB7B', nr)
    print 'Session key = ', _hexlify (deriveSessionKey (_nonce, ourNonce = _ourNonce, isDES=True))
