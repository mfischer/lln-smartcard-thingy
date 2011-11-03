#!/usr/bin/env python2
import sys

def getNonce():
    print("Enter a nonce or <Enter> for default value.\nThe nonce should be 8 bytes-long in hexadecimal\nDefault: 11 22 33 44 55 66 77 88.")
    nonce = raw_input("Nonce: ")
    if checkNonce(nonce):
        return toBytes(nonce)

def checkNonce(nonce):
    if len(nonce) == 0:
        n = toBytes("11 22 33 44 55 66 77 88")
    else:
        try:
            n = toBytes(nonce)
            if len(n)==8:
                print("nonce ok")
            else:
                raise Exception
        except:
            print(nonce+" is not valid, selecting default value")
            n = toBytes("11 22 33 44 55 66 77 88")


if __name__ == "__main__":
    s = SmartUtils()
    s.poll()

    nonce = getNonce()
    s.auth(n)
