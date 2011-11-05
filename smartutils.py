import smartcard
import sys
import subprocess

from smartcard.util import toHexString, toBytes
from binascii import hexlify, unhexlify

from desfire import challenge, crc

class SmartUtils:

    def __init__(self):

        self.session = None
        if len(smartcard.listReaders()) == 0:
            print("No reader found")
        else:
            self.session = smartcard.Session()
            print("Reader selected")


    def poll(self):
        """Do the polling
        
        Poll the tag, show the full hex response if not ending with 0x90 0x00
        """
        sys.stdout.write("Polling... ")
        data, sw1, sw2 = self.session.sendCommandAPDU([0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x02, 00])
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes ("FF C0 00 00 " + hex(sw2)[2:]))
        if sw1 == 0x90 and sw2 == 0x00:
            sys.stdout.write("[Done]\n")
        else:
            print("Error: "+toHexString(data)+" "+toHexString([sw1, sw2]))

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
        
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes( "FF C0 00 00 0F" ) )
        #print(toHexString(data)+", "+toHexString([sw1, sw2]))

        n_t = crc.mergeList( data[3:11] )
        n2_t = unhexlify( n_t )
        response, nr = challenge.generateResponse(n2_t)
        
        cmd = "FF 00 00 00 19 D4 40 01 90 AF 00 00 10"
        cmd += hexlify(response)
        cmd += "00"
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes(cmd) )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes("FF C0 00 00 0F") )
        n2_r = crc.mergeList( data[3:11] )

        if challenge.verifyResponse(n2_r, nr):
            sys.stdout.write("[Done]\n")
        else:
            sys.stdout.write("[Fail]\n")

    def erase_all(self, key = 8*"00"):
        def action ():
            data, sw1, sw2 = self.session.sendCommandAPDU([0xff, 0x00, 0x00, 0x00, 0x07, 0xd4, 0x40, 0x90, 0xfc, 0x00, 0x00, 0x00])
            if sw1 != 0x61:
                return False
            elif sw1 == 0x61 and sw2 != 0:
                data, sw1, sw2 = self.session.sendCommandAPDU( toBytes("FF C0 00 00")+[sw2] )
                #print 'Data: ', map (hex, data)
                #print 'sw1: ', hex(sw1)
                #print 'sw2: ', hex(sw2)
                return True
        self._withStatusMsg('Erasing Card', action)



    def _withStatusMsg(self, msg, call):
        sys.stdout.write (msg + ' ...')
        if call ():
            sys.stdout.write('[Done]\n')
        else:
            sys.stdout.write('[Fail]\n')
