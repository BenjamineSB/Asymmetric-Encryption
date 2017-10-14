#!/usr/bin/python

# Designed by: Mr. S. Benjamine
# Designed for: SSS-assignment2
# Reg-no: IT15156952

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5

KEY_LENGTH = 1024 #key size in bit
#to secure from bruteforce attack use lengthy key size

RANDOM_NO = Random.new().read #random no need to create RSA

#generate RSA key pairs (public key|private key) for bob and alice
KEYPAIR_BOB = RSA.generate(KEY_LENGTH, RANDOM_NO)
KEYPAIR_ALICE = RSA.generate(KEY_LENGTH, RANDOM_NO)

#get public key from bob and alice
PUBLIC_KEY_BOB = KEYPAIR_BOB.publickey();
PUBLIC_KEY_ALICE = KEYPAIR_ALICE.publickey();

#get the plane text messaged
MESSAGE_TO_BOB = raw_input('MESSAGE TO BOB FROM ALICE:')
MESSAGE_TO_ALICE = raw_input('MESSAGE TO ALICE FROM BOB:')

#calculate the hash value of the message 
HASH_OF_MESSAGE_TO_BOB = MD5.new(MESSAGE_TO_BOB).digest()
HASH_OF_MESSAGE_TO_ALICE = MD5.new(MESSAGE_TO_ALICE).digest()

print '\nHASH VALUES OF MESSAGES'
print 'HASH MESSAGE TO BOB FROM ALICE: ' + HASH_OF_MESSAGE_TO_BOB
print 'HASH MESSAGE TO ALICE FROM BOB: ' + HASH_OF_MESSAGE_TO_ALICE
print 'HASH VALUES ARE NOT VISIBLE. THEY ARE ONE WAY ENCRYPTION'

#generate digital signature by using private keys of bob and alice
#we cannot extract the private key seperatly so use KEYPAIR which contain both public and private keys
SIGNATURE_BOB = KEYPAIR_BOB.sign(HASH_OF_MESSAGE_TO_BOB, '')
SIGNATURE_ALICE = KEYPAIR_ALICE.sign(HASH_OF_MESSAGE_TO_ALICE, '')

print '\nDIGITAL SIGNATURES'
print 'DIGITAL SIGNATURE OF BOB:'
print SIGNATURE_BOB
print 'DIGITAL SIGNATURE OF ALICE:'
print SIGNATURE_ALICE

#asymmetric encryption by bob and alice public key
#encrypted output is in 32bit format
ENCRYPTED_MESSAGE_TO_BOB = PUBLIC_KEY_BOB.encrypt(MESSAGE_TO_BOB, 32) #done by ALLICE
ENCRYPTED_MESSAGE_TO_ALICE = PUBLIC_KEY_ALICE.encrypt(MESSAGE_TO_ALICE, 32) #done by BOB

print '\nASYMMETRIC ENCRYPTED MESSAGES BY BOB & ALICE PUBLIC KEYS'
print 'ENCRYPTED MESSAGE OF BOB FROM ALICE:'
print ENCRYPTED_MESSAGE_TO_BOB
print 'ENCRYPTED MESSAGE OF ALICE FROM BOB:'
print ENCRYPTED_MESSAGE_TO_ALICE

#asymmetric decryption by bob and alice private key
DECRYPTED_MESSAGE_TO_BOB = KEYPAIR_BOB.decrypt(ENCRYPTED_MESSAGE_TO_BOB) #don by BOB
DECRYPTED_MESSAGE_TO_ALICE = KEYPAIR_ALICE.decrypt(ENCRYPTED_MESSAGE_TO_ALICE) #done by ALLICE

print '\nASYMMETRIC DECRYPTED MESSAGES BY BOB & ALICE PRIVATE KEYS'
print 'DECRYPTED MESSAGE OF BOB SENT FROM ALLICE: ' + DECRYPTED_MESSAGE_TO_BOB
print 'DECRYPTED MESSAGE OF ALICE SENT FROM BOB: ' +  DECRYPTED_MESSAGE_TO_ALICE

#signature validation and hash validation
#for HASH we are using MD5 (need to do same as before in hasing the original message)
DECRYPTED_HASH_MESSAGE_TO_BOB = MD5.new(DECRYPTED_MESSAGE_TO_BOB).digest() #done by BOB
DECRYPTED_HASH_MESSAGE_TO_ALICE = MD5.new(DECRYPTED_MESSAGE_TO_ALICE).digest() #done by ALLICE

#checking the hash
#by BOB
if PUBLIC_KEY_ALICE.verify(DECRYPTED_HASH_MESSAGE_TO_ALICE,SIGNATURE_ALICE):
	MESSAGE1 = 'BOB RECEIVED THE CORRECT MESSAGE FROM ALLICE'
else:
	MESSAGE1 = 'BOB DID NOT RECEIVE THE CORRECT MESSAGE FROM ALLICE'

#by ALLICE
if PUBLIC_KEY_BOB.verify(DECRYPTED_HASH_MESSAGE_TO_BOB,SIGNATURE_BOB):
	MESSAGE2 = 'ALICE RECEIVED THE CORRECT MESSAGE FROM BOB'
else:
	MESSAGE2 = 'ALICE DID NOT RECEIVE THE CORRECT MESSAGE FROM BOB'

#print the check result
print '\n' + MESSAGE1 + '\n' + MESSAGE2

