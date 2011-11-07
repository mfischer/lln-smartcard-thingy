#!/usr/bin/env python2

OP = 0x00
NO_CHANGES = 0x0c
ILLEGAL_COMMAND_CODE = 0x1c
INTEGRITY_ERR = 0x1e
NO_SUCH_KEY = 0x40
LENGTH_ERR = 0x7e
PERM_DENIED = 0x9d
PARAM_ERR = 0x9e
APP_NOT_FOUND = 0xa0
APP_INTEGRITY_ERROR = 0xa1
AUTH_ERR = 0xae
ADD_FRAME = 0xaf
BOUND_ERROR = 0xbe
COMMAND_ABRT = 0xca
DUPLICATE_ERR = 0xde
FILE_NOT_FOUND = 0xf0

def _parseFullResponse (resp):
    direction = resp[0]
    tag = None
    data = None
    sw1 = None
    sw2 = None
    if resp[1] is 0x41:
        tag = resp[2]
        sw1 = resp[-4]
        sw2 = resp[-3]
        data = resp[3:-4:]
    else:
        #FIXME handle this
        pass 
    return (tag, data, sw1, sw2)


def evaluateResponse (resp):
    """
    Returns the DESFire's sw1, sw2 given the full response.
    """
    _tag, data, sw1, sw2 = _parseFullResponse (resp)
    return (data, sw1, sw2)
