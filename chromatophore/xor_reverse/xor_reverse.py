from random import randrange
import sys


xor_key = 23

def get_raw_sc(input_file):
    input_file = input_file
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
        return(file_shellcode)
    except FileNotFoundError:
        sys.exit("Supplied input file not found!")


def xor_reverse(input_file):

    data = get_raw_sc(input_file)
    shellcode = list(data)

    hexbytes = ', '.join(hex(x ^ xor_key) for x in shellcode[::-1])

    # Print in reverse order as hex bytes
    ret = 'unsigned char reversed_payload [{}] = {}'.format(
        len(shellcode),
        '{' + hexbytes + '};'
    )
    
    return ret