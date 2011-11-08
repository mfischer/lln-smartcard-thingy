#!/usr/bin/env python2

import unittest
from challenge import generateResponse, verifyResponse, deriveSessionKey
from binascii import hexlify, unhexlify

class TestChallengeModule(unittest.TestCase):

    def setUp(self):
        self.nonce  = 0x6e7577944adffc0c
        self.ourNonce = 0x1122334455667788
        self.masterKey = 16*'00'

    def testGenerateResponse(self):
        _nonce = unhexlify (hex (self.nonce)[2:])
        _ourNonce = unhexlify (hex (self.ourNonce)[2:])
        response, nr = generateResponse (_nonce, key = self.masterKey, ourNonce = _ourNonce)
        self.assertEqual (hexlify(nr), hex(self.ourNonce)[2:])
        self.assertEqual (hexlify(response), 'cd72dfc6e6d040a47633d04c9a2ffd83')

    def testVerifyResponse (self):
        self.assertTrue (verifyResponse ('AD6CC16025CCFB7B', unhexlify(hex(self.ourNonce)[2:])))

    def testDeriveSessionKey (self):
        nonce = 'cb06b4f59a82f6f0'
        ourNonce = 'aabbccddeeff1122'
        sessionKey = deriveSessionKey (unhexlify (nonce), unhexlify (ourNonce), True)
        self.assertEqual (sessionKey, unhexlify('aabbccddcb06b4f5'))


if __name__ == '__main__':
    unittest.main()
