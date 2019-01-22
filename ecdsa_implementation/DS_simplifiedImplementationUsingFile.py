# Simple implementation of Digital Signature using user's file as Message or Data.

from hashlib import sha256
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey
#import pickle          #   Can be used to read/write python objects from/to file.  


def UserFile():
    #   User's file or Data acceptance begins.
    with open('SampleUserFile.txt', 'r') as Ufile:              
    #   'r' opens the file in read mode.
    #   Reading couldn't be done on .docx, .xlsx, .pdf files. So far, only .txt is successful.
        dataFile = Ufile.read()
        hashedFile = (sha256(dataFile.encode())).hexdigest()    #   Encode and Hash the file.
        return hashedFile


def keyPairGenerator():
    #   Very easy way to derive private and public keys from ecdsa beigns.
    #   Another way to generate the private and public keys. Private key gotten but Public. 

    private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
    string_private_key = private_key.to_string()

    #   Now derive the public key from the Private Key
    public_key = private_key.get_verifying_key()    # This verifying key is the public key.
    string_public_key = public_key.to_string()
    #print('')
    #print("The Private key is: ", string_private_key)
    print('')
    print("The Public key is: ", string_public_key)

    return string_private_key, string_public_key



    #   Generation of Private and Public keys ends. 

def signFile(string_private_key, hashedFile):
    #   Signing of the Message/Data using Private key and Hashed Message begins. 

    sgkey = ecdsa.SigningKey.from_string(string_private_key, curve=ecdsa.SECP256k1)
    print('')
    print("The Signing Key is: ", sgkey)

    digitalSig = sgkey.sign(hashedFile.encode()) # This throws error if not encoded.
    print('')
    print("The Digital Signature is: ", digitalSig)

    return digitalSig
    #   Signing of the Message/Data using Private key and Hashed Message ends here.


def verifyFile(string_public_key, digitalSig, hashedFile):
    #   Now the verification phase begins.

    #   Hash of the data/message is already done and stored in hashedMsg so only decryption to be done. 

    verificationKey = ecdsa.VerifyingKey.from_string(string_public_key, curve=ecdsa.SECP256k1)

    # To convert verificationkey to string to see correctly. Next line of code can be activated and printed if needed.

    string_verificationkey = verificationKey.to_string()
    print('')
    print("The Verification Key is: ", verificationKey) 
    print('')
    print("The String Verification Key is: ", string_verificationkey)

    assert  verificationKey.verify(digitalSig, hashedFile.encode()), "Sorry! Verification failed."

    print('')
    print("Congratulations! Verification was successful. Thank you.")
    #   Verification phase ends here.


#   Main method of app.
#   Display Intro.
def main():
    print('')

    print("******************* Sign and Verify Data with Digital Signature using ECDSA *********************")

    print('')

    print ("Ni hao. Welcome.: ")

    print('')

    hashedFile = UserFile()

    string_private_key, string_public_key = keyPairGenerator()

    digitalSig = signFile(string_private_key, hashedFile)

    verifyFile(string_public_key, digitalSig, hashedFile)

    #   Main method ends here. 

#   Program execution time. 

main()



