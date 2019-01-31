# This is a command-line application.
# Implementation of Digital Signature using user's typed input.

from hashlib import sha256
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey


def userInput():
    message = input('Ni hao .... Please enter message to be signed digitally.: ')

    hashedMsg = (sha256(message.encode())).hexdigest()

    print('')
    print ("The hashed message is: ", hashedMsg)
    return hashedMsg


#   Very easy way to derive private and public keys from ecdsa beigns.
#   Another way to generate the private and public keys. Private key gotten but Public. 
def generateKeyPair():
    private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
    string_private_key = private_key.to_string()

    #   Now derive the public key from the Private Key
    public_key = private_key.get_verifying_key()    # This verifying key is the public key.
    string_public_key = public_key.to_string()
    return string_private_key, string_public_key

print('')
#print('The private key not string is: ', private_key)
#print("The Private key is: ", string_private_key)
print('')
#print("The Public key is: ", string_public_key)

#   Generation of Private and Public keys ends. 


    #   Signing of the Message/Data using Private key and Hashed Message begins. 
def SignData(string_private_key, hashedMsg):
    sgkey = ecdsa.SigningKey.from_string(string_private_key, curve=ecdsa.SECP256k1, hashfunc = sha256)
    print('')
    print("The Signing Key is: ", sgkey)

    digitalSig = sgkey.sign(hashedMsg.encode(), hashfunc = sha256) # This throws error if not encoded.
    print('')
    print("The Digital Signature is: ", digitalSig)
    return digitalSig
    #   Signing of the Message/Data using Private key and Hashed Message ends here.


#   Now the verification phase begins.
def VerifyData(string_public_key, digitalSig, hashedMsg):
    #   Hash of the data/message is already done and stored in hashedMsg so only decryption to be done. 
    verificationKey = ecdsa.VerifyingKey.from_string(string_public_key, curve=ecdsa.SECP256k1, hashfunc = sha256)
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


#   The main function to the app.
#   Display Intro.
def main():
    print('')
    print("******************* Sign and Verify Data with Digital Signature using ECDSA *********************")

    print('')

    print("Ni hao. Welcome.: ")

    print('')

    hashedMsg = userInput()

    string_private_key, string_public_key = generateKeyPair()

    digitalSig = SignData(string_private_key, hashedMsg)

    VerifyData(string_public_key, digitalSig, hashedMsg)

#   Execution time.
main()
