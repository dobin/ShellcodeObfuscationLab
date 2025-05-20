#!/usr/bin/env python3
from base64 import b64encode
import sys


def base64(input_file) -> str:
    try:
        plaintext = open(input_file, "rb").read()
    except:
        print("File argument needed! %s <raw payload file>" % sys.argv[0])
        sys.exit()

    b64 = b64encode(plaintext).decode('utf-8')

    b64 = 'const char* base64 = "' + b64 + '";\n'
    b64 += 'DWORD shellcodeLen = ' + str(len(plaintext)) + ';\n'

    return b64

