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

    def auth(self,key_num=0x00):
        """Authentication process
        
        Do the authentication 1st step, get the tag nonce and do byte shifting
        """
        sys.stdout.write("Authenticating... ")
        # auth 1st step
        cmd = toBytes ("FF 00 00 00 0A D4 40 01 90 0A 00 00 01")
        cmd.append(key_num)
        cmd.append(0x00)

        data, sw1, sw2 = self.session.sendCommandAPDU( cmd )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        # get response
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes( "FF C0 00 00 0F" ) )

        n_t = crc.mergeList( data[3:11] )
        n2_t = unhexlify( n_t )
        # compute des encryption of nonce
        response, nr = challenge.generateResponse(n2_t)
        
        # auth 2sd step
        cmd = "FF 00 00 00 19 D4 40 01 90 AF 00 00 10"
        cmd += hexlify(response)
        cmd += "00"
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes(cmd) )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        # get response
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes("FF C0 00 00 0F") )
        n2_r = crc.mergeList( data[3:11] )

        if challenge.verifyResponse(n2_r, nr):
            sys.stdout.write("[Done]\n")
            return True
        else:
            sys.stdout.write("[Fail]\n")
            return False

        
    def selectApplication(self,aid=0x00):
        # selct application
        cmd = toBytes ("FF 00 00 00 0C D4 40 01 90 5A 00 00 03")
        cmd.append(aid)
        if aid < 0xFF:
            cmd.append(0x00)
            cmd.append(0x00)
        elif aid < 0xFFFF:
            cmd.append(0x00)
        cmd.append(0x00)
            
        data, sw1, sw2 = self.session.sendCommandAPDU( cmd )
        
        # get response
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes( "FF C0 00 00 07" ) )
        if data[3]==0x91 and data[5]==0x90:
            print "Application "+str(aid)+" selected"
        else:
            print "Error selection application "+str(aid)
