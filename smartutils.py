import smartcard
import sys
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
            sys.stdout.write("[Fail 0]\n")
            return None
        
        data, sw1, sw2 = self.getAnswer (sw2)
        dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
        if (dfsw1 != 0x91):
            sys.stdout.write('[Fail 1]\n')
            return None

        n_t_enc = crc.mergeList(dfdata)
        n2_t = unhexlify( n_t_enc )
        response, nr, nt = challenge.generateResponse(n2_t, key)
        nt = hexlify(nt)
        #response, nr = challenge.generateResponse(n2_t, key)
        
        cmd = "FF 00 00 00 19 D4 40 01 90 AF 00 00 10"
        cmd += hexlify(response)
        cmd += "00"
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes(cmd) )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail 2]\n")
            return None
        
        data, sw1, sw2 = self.getAnswer (sw2)

        dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
        if not errors.isOpOk (dfsw1, dfsw2):
            sys.stdout.write('[Fail 3]\n')
            return None

        n2_r = crc.mergeList(dfdata)

        if challenge.verifyResponse(n2_r, nr, key):
            sys.stdout.write("[Done]\n")
            #if challenge.isDES (key) or (len(key) == 8):
                #print "We're using DES for deriving the sessionkey, nonces were nr: %s, nt: %s" % (hexlify(nr), nt)
            return challenge.deriveSessionKey (unhexlify(nt), nr, challenge.isDES (key) or len(key) == 8)
        else:
            sys.stdout.write("[Fail 4]\n")

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


    def createApplication (self, aid = 0x01, keySetup = 0x0b, numKeys = 0x01):
        def _createApplication ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x0e,
                                                           0xd4, 0x40, 0x01, 0x90, 0xca,
                                                           0x00, 0x00, 0x05]
                                                        + [aid, 0x00, 0x00]
                                                        + [keySetup]
                                                        + [numKeys] + [0x00])
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

    def changeKey (self, keyNo, newKey, currentSessionKey, authKeyDifferent = True, currentKey = None):
        """
        After having selected an AID with selectApplication before
        this function allows for changing the key with number 'keyNo'

        The special case where the key to change is identical
        with the key used to authenticate is denoted by setting
        authKeyDifferent to 'False'
        """
        #if authKeyDifferent:
            #assert len(newKey) is 16
            #data = int(newKey, 16) ^ int(currentKey, 16)
            ##FIXME decide whether we want the old calculateFlippedCrc interface with lists instead.
            #crcxor = crc.calculateFlippedCrc (hex(data)[2:])
            #crcnk = crc.calculateFlippedCrc (newKey)
            #frame = toBytes(hex(data)[2:]) + crcxor + crcnk + [0x0,0x0,0x0,0x0]
            #print 'Frame: ', frame

        print 'Trying to change the same key'
        crcnk = crc.calculateFlippedCrc (newKey)
        frame = toBytes (newKey) + toBytes(hex(crcnk)[2:]) + [0x0,0x0,0x0,0x0,0x0,0x0]
        #print 'Frame:', map(hex,frame)
        _currentSessionKey = crc._listFromStr (currentSessionKey)
        #print 'Current session key', map (hex, _currentSessionKey)
        _frame_deciphered = hexlify (challenge.decipherSendMode (frame, key = _currentSessionKey))
        #print 'Frame deciphered: ', _frame_deciphered
        send_data = [0xff, 0x00, 0x00, 0x00, 0x22, 0xd4, 0x40, 0x01, 0x90, 0xc4, 0x00, 0x00, 0x19] \
                  + [keyNo] + crc._listFromStr (_frame_deciphered) + [0x00]

        #print 'Sent: ', map(hex, send_data)
        data, sw1, sw2 = self.session.sendCommandAPDU(send_data)
        data, dfsw1, dfsw2 = self.getAnswer (sw2)
        print 'Data from DESFire', map(hex,data)
        print 'SW1 from DESFire', hex(dfsw1)
        print 'SW2 from DESFire', hex(dfsw2)
        
        def createStdDataFile(self, fileNo = 0x01, comSet = 0x03, accRights = [0xE0, 0x00], fileSizeLSB):
            def _createStdDataFile ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x10,
                                                           0xd4, 0x40, 0x01, 0x90, 0xcd,
                                                           0x00, 0x00, 0x07]
                                                           + [fileNo] + [comSet] + [accRights] 
                                                           + fileSizeLSB + [0x00])
            if sw1 != 0x61:
                return False[0x00]
            else:
                data, sw1, sw2 = self.getAnswer (sw2)
                dfdata, dfsw1, dfsw2 = errors.evaluateResponse (data)
                return errors.isOpOk (dfsw1, dfsw2)
        self._createStdDataFile('Creating standard data file #%x' % fileNo, _createStdDataFile)


    def _withStatusMsg(self, msg, call):
        sys.stdout.write (msg + ' ...')
        if call ():
            sys.stdout.write('[Done]\n')
        else:
            sys.stdout.write('[Fail]\n')
