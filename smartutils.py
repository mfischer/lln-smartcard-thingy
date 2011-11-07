import smartcard
import sys
import subprocess

from smartcard.util import toHexString, toBytes
from binascii import hexlify, unhexlify

from desfire import challenge, crc, errors

class SmartUtils:

    def __init__(self):
        self.session = None
        if len(smartcard.listReaders()) == 0:
            print("No reader found")
        else:
            self.session = smartcard.Session()
            print("Reader selected")

    def getAnswer (self, length):
        """
        Given a length (in bytes) this will retrieve the answer.
        """
        return self.session.sendCommandAPDU( [0xff, 0xc0, 0x00, 0x00] + [length])


    def poll(self):
        """Do the polling
        
        Poll the tag, show the full hex response if not ending with 0x90 0x00
        """
        #sys.stdout.write("Polling... ")

        def _poll ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x02, 00])
            data, sw1, sw2 = self.getAnswer (sw2)
            if sw1 == 0x90 and sw2 == 0x00:
                return True
            else:
                return False

        self._withStatusMsg ('Polling', _poll)

    def auth(self, key = 16*'00', key_num=0x00):
        """Authentification process
        
        Do the authentification 1st step, get the tag nonce and do byte shifting
        """
        sys.stdout.write("Authenticating... ")
        cmd = toBytes ("FF 00 00 00 0A D4 40 01 90 0A 00 00 01")
        cmd.append(key_num)
        cmd.append(0x00)
        data, sw1, sw2 = self.session.sendCommandAPDU( cmd )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        data, sw1, sw2 = self.getAnswer (sw2)
        dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
        if (dfsw1 != 0x91):
            sys.stdout.write('[Fail]\n')
            return False

        n_t = crc.mergeList(dfdata)
        n2_t = unhexlify( n_t )
        response, nr = challenge.generateResponse(n2_t, key)
        
        cmd = "FF 00 00 00 19 D4 40 01 90 AF 00 00 10"
        cmd += hexlify(response)
        cmd += "00"
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes(cmd) )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        data, sw1, sw2 = self.getAnswer (sw2)

        dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
        if not errors.isOpOk (dfsw1, dfsw2):
            sys.stdout.write('[Fail]\n')
            return False

        n2_r = crc.mergeList(dfdata)

        if challenge.verifyResponse(n2_r, nr, key):
            sys.stdout.write("[Done]\n")
        else:
            sys.stdout.write("[Fail]\n")

    def eraseAll(self, key = 16*"00"):
        def _eraseAll ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x08, 0xd4, 0x40, 0x01, 0x90, 0xfc, 0x00, 0x00, 0x00])
            if sw1 != 0x61:
                return False
            elif sw1 == 0x61 and sw2 != 0:
                data, sw1, sw2 = self.getAnswer (sw2)
                dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
                return errors.isOpOk (dfsw1, dfsw2)
        self._withStatusMsg('Erasing Card', _eraseAll)


    def createApplication (self, aid = 0x01, key_setup = 0x0b, num_keys = 0x01):
        def _createApplication ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x0e,
                                                           0xd4, 0x40, 0x01, 0x90, 0xca,
                                                           0x00, 0x00, 0x05]
                                                        + [aid, 0x00, 0x00]
                                                        + [key_setup]
                                                        + [num_keys] + [0x00])
            if sw1 != 0x61:
                return False
            elif sw1 == 0x61:
                data, sw1, sw2 = self.getAnswer (sw2)
                dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
                return errors.isOpOk (dfsw1, dfsw2)

        self._withStatusMsg('Creating applicaton #%x' % aid, _createApplication)

    def selectApplication (self, aid):
        def _selectApplication ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x0c,
                                                           0xd4, 0x40, 0x01, 0x90, 0x5a,
                                                           0x00, 0x00, 0x03]
                                                        + [aid, 0x00, 0x00] + [0x00])
            if sw1 != 0x61:
                return False
            else:
                data, sw1, sw2 = self.getAnswer (sw2)
                dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
                return errors.isOpOk (dfsw1, dfsw2)
        self._withStatusMsg('Selecting applicaton #%x' % aid, _selectApplication)



    def _withStatusMsg(self, msg, call):
        sys.stdout.write (msg + ' ...')
        if call ():
            sys.stdout.write('[Done]\n')
        else:
            sys.stdout.write('[Fail]\n')
