import ecdsa
from ecdsa import SigningKey, VerifyingKey
#from ecdsa import  SECP256k1   # This is useful to avoid manual curve key computations.#SECP256k1 
# can be changed based on the desired specifications in the SEC document.
# Refer to downloaded document in Block_chain_stuff ---- Recommended EC domain parameters.
#
import os
import sys
import numpy as np
from hashlib import sha256
import binascii


from ecdsa.util import string_to_number, number_to_string

# Based on secp256k1, http://www.oid-info.com/get/1.3.132.0.10

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)

generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)

oid_secp256k1 = (1, 3, 132, 0, 10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1)
ec_order = _r
curve = curve_secp256k1
generator = generator_secp256k1


def random_secret():        #   Method to generate private key. 
    byte_array = os.urandom(32)
        
    joinArray = "".join([str(i) for i in byte_array])
    convert_to_int = int(joinArray)
    
    encode_int = int(hex(convert_to_int), 16)

    return encode_int

#   Now going to generate a new private key.
secret = random_secret()    #Generate a new private key.

#encodeSecrete = hex(secret)
byteSecret = (str(secret).encode())
hashSecrete = sha256(byteSecret)
privkey = hashSecrete.hexdigest()


print("The Private key is: ", privkey)

#print("The Generator is: ", generator)

#   Getting the X and Y coodinates.
#X = generator._Point__x
#Y = generator._Point__y

#print(X)
#print(Y)

#merger = (int(str(X) + str(Y))) #   Putting X and Y together as one number.

#print(merger)

# Get the public key point.
  
#point = (secret * merger)

point = (np.multiply(secret, generator)) # This also works--Numpy. 

#print("Elliptive Curve point:", point)


def get_point_pubkey(point):
    if point.y() & 1:
        key = '03' + '%064x' % point.x()
    else:
        key = '02' + '%064x' % point.x()
    return int(key, 16)

pubS = str(get_point_pubkey(point))
pubEnc = sha256(pubS.encode())
pubkey = pubEnc.hexdigest()

#print("The public key is:", hex(get_point_pubkey(point)))
print("The Public key is:", pubkey)

#   An effective way?
# Generate the key pair from a SECP256K1 elliptic curve.
def keyPair():
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()

    return sk, pk 


#   Prompt user for data input.
def inputData():
    global message
    message = input("Ni hao. Please enter the message to be signed.: ")
    #return message
#   The Data or Message to be signed. This can be improved to accept various kinds of data.
#message=''
def messageData(message):
    global msgHashed
    msgHashed = (sha256(message.encode())).hexdigest()
    return msgHashed


#   Signing a message with private key.
def sign(privkey, msgHashed):
        sk = ecdsa.SigningKey.from_string(binascii.unhexlify(privkey), curve=ecdsa.SECP256k1, hashfunc = sha256)
        signature = binascii.hexlify(sk.sign(binascii.unhexlify(msgHashed), hashfunc=sha256))
        global theSign
        theSign = signature
        return signature


def verify(pubkey, msgHashed, signature):
        #   pubkey:hex pubkey, not hex_compressed
        try:
            vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(pubkey), curve=ecdsa.SECP256k1, hashfunc=sha256)
    
            sigDec = (sha256(signature).hexdigest())
            vk.verify(binascii.unhexlify(sigDec), binascii.unhexlify(msgHashed))
        except ecdsa.BadSignatureError:
            return False
            

print('')

print("******************* Sign and Verify Data *********************")

print('')

inputData()

keyPair()

sign(privkey, messageData(message))

print("The message entered was: ", message)
print("The message hashed is now: ", msgHashed)
print("The Signature for the message is: ", theSign)

sigN = sign(privkey, msgHashed)

verify(pubkey, msgHashed, theSign)
