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

    def auth(self,n_r,key_num=0x00):
        """Authentification process
        
        Do the authentification 1st step, get the tag nonce and do byte shifting
        """
        #sys.stdout.write("Authentificating... ")
        print("Authentificating... ")
        cmd = toBytes ("FF 00 00 00 0A D4 40 01 90 0A 00 00 01")
        cmd.append(key_num)
        cmd.append(0x00)
        data, sw1, sw2 = self.session.sendCommandAPDU( cmd )
        if sw1!=0x61 or sw2!=0x0F:
            sys.stdout.write("[Fail]\n")
            return False
        
        data, sw1, sw2 = self.session.sendCommandAPDU( toBytes( "FF C0 00 00 0F" ) )
        #print(toHexString(data)+", "+toHexString([sw1, sw2]))

        print data[3:]        
        n_t = crc.mergeList( data[3:] )
        print n_t
        n2_t = unhexlify( n_t )
        print n2_t
        response, nr = challenge.generateResponse(n_t)
        print(n_t, response, nr)

        #sys.stdout.write("[Done]\n")
        
    def _encDES(self,inp):
        nonce = ""
        for b in inp:
            nonce += str(b)
        
        # not working, return error code
        return subprocess.check_call("echo "+nonce+" | xxd -p -r | openssl enc -des -d -K 0 -iv 0 -nopad | xxd -p",shell=True)
        
