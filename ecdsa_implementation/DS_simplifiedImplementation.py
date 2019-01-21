# Simple implementation of Digital Signature

from hashlib import sha256
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey


#   Display Intro.
print('')

print("******************* Sign and Verify Data with Digital Signature using ECDSA *********************")

print('')

print ("Ni hao. Welcome.: ")

print('')

message = input('Please enter message to be signed digitally.: ')

hashedMsg = (sha256(message.encode())).hexdigest()

print('')
print ("The hashed message is: ", hashedMsg)


#   Very easy way to derive private and public keys from ecdsa beigns.
#   Another way to generate the private and public keys. Private key gotten but Public. 

private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
string_private_key = private_key.to_string()

#   Now derive the public key from the Private Key
public_key = private_key.get_verifying_key()    # This verifying key is the public key.
string_public_key = public_key.to_string()


print('')
print("Another Private key is: ", string_private_key)
print('')
print("Another Public key is: ", string_public_key)

#   Generation of Private and Public keys ends. 


#   Signing of the Message/Data using Private key and Hashed Message begins. 

sgkey = ecdsa.SigningKey.from_string(string_private_key, curve=ecdsa.SECP256k1)
print('')
print("The Signing Key is: ", sgkey)

digitalSig = sgkey.sign(hashedMsg.encode()) # This throws error if not encoded.
print('')
print("The Digital Signature is: ", digitalSig)

#   Signing of the Message/Data using Private key and Hashed Message ends here.
#  

#   Now the verification phase begins.

#   Hash of the data/message is already done and stored in hashedMsg so only decryption to be done. 

verificationKey = ecdsa.VerifyingKey.from_string(string_public_key, curve=ecdsa.SECP256k1)
# To convert verificationkey to string to see correctly. Next line of code can be activated and printed if needed.
string_verificationkey = verificationKey.to_string()
print('')
print("The Verification Key is: ", verificationKey) 
print('')
print("The String Verification Key is: ", string_verificationkey)


assert  verificationKey.verify(digitalSig, hashedMsg.encode()), "Sorry! Verification failed."

print('')
print("Congratulations! Verification was successful. Thank you.")

#   Verification phase ends here.

print('')

# Someone tried below codes in stackoverflow and works.
#private_key = SigningKey.generate(curve=SECP256k1)
#string_private_key = private_key.to_string()
# Then to Sign to DS
#SigningKey.from_string(string_private_key, curve=SECP256k1)    ---- Confirmed. It works. 

#  Another one from stackoverflow which is said to work.---https://stackoverflow.com/questions/34451214/how-to-sign-and-verify-signature-with-ecdsa-in-python
# SECP256k1 is the Bitcoin elliptic curve
#sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) 
#vk = sk.get_verifying_key()
#sig = sk.sign(b"message")
#vk.verify(sig, b"message") # True
# Check also:  https://crypto.stackexchange.com/questions/62100/ecdsa-signing-and-verification-between-python-and-js

#   To play with Signing Files, give the following a try.
#with open('file.txt', 'rb') as f:
#    dataFile = f.read()
#    hasher.update(dataFile)
#print(hasher.hexdigest())