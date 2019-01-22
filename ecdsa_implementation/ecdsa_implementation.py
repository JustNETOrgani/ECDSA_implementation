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
import re


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
    global byte_array
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
#string_prvkey = privkey.to_string()

print('The Secret is: ', secret)            #   This is just set of numbers.
print("The Private key is: ", privkey)      #   This is hex numbers.

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

px =point._Point__x
py =point._Point__y

print('The byte array is: ', byte_array)

print('The PointX is: ', px)
print('The PointX is: ', py)

mergePointXnY = px+py


#pointStr = str(mergePointXnY)
#pointMg = point.replace(',', '')
#pointMg =(re.sub("[ ()]", " ", pointStr))  #   This removes the parenthesis and comma.
#int_convert = int(pointMg)
    
encode_int = int(hex(mergePointXnY),16)
#bytesEncode_int = encode_int.to_bytes(10, byteorder='big')
#bytesForm = bytes(encode_int)

pointToString = (str(encode_int).encode())
#print('The Public key2 is: ', pointToString)
hashPoint = sha256(pointToString)
pubkey2 = (int(hashPoint.hexdigest(),16)).to_bytes(64, byteorder='little')
hexpubkey2 = (sha256(str(pubkey2).encode()))
print('The Public key2 is: ', hexpubkey2)

#print("Elliptive Curve point:", point)


def get_point_pubkey(point):
    if point.y() & 1:
        key = '03' + '%064x' % point.x()
    else:
        key = '02' + '%064x' % point.x()
    #return int(key, 16)
    return key

pubS = str(get_point_pubkey(point))
pubEnc = sha256(pubS.encode())
pubkey = (pubEnc.hexdigest())
#string_pubkey = pubkey.to_string()

#print("The public key is:", hex(get_point_pubkey(point)))
print("The Public key is:", pubkey)


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
def sign(string_prvkey, msgHashed):
        thesignkey = ecdsa.SigningKey.from_string(binascii.unhexlify(privkey), curve=ecdsa.SECP256k1, hashfunc = sha256)
        signature = thesignkey.sign(msgHashed.encode(), hashfunc = sha256) # This throws error if not encoded.
        global theSign
        theSign = signature
        return signature


def verify(pubkey, msgHashed, signature):
    #   pubkey:hex pubkey, not hex_compressed
    #vk = ecdsa.VerifyingKey.from_string(string_pubkey, curve=ecdsa.SECP256k1, hashfunc = sha256)
    
    #sigDec = (sha256(signature).hexdigest())
    #vk.verify(digitalSig, msgHashed.encode(), "Sorry! Verification failed."
   
    vk = ecdsa.VerifyingKey.from_string((pubkey), curve=ecdsa.SECP256k1, hashfunc = sha256)
    assert vk.verify(signature, msgHashed.encode()), 'Oh! Sorry, verification failed'

    print('')
    print("Congratulations! Verification was successful. Thank you.")

print('')

print("******************* Sign and Verify Data *********************")

print('')

inputData()

sign(privkey, messageData(message))

print("The message entered was: ", message)
print("The message hashed is now: ", msgHashed)



print("The Signature for the message is: ", theSign)

sigN = sign(privkey, msgHashed)

verify(pubkey2, msgHashed, theSign)
