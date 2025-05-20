import sys


def get_raw_sc(input_file):
    input_file = input_file
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
        return(file_shellcode)
    except FileNotFoundError:
        sys.exit("Supplied input file not found!")


def xor_single(input_file):
    shellcode = get_raw_sc(input_file)
    shellcode = list(shellcode)

    xor_key = 23

    ret = ""
    ret += 'unsigned int xorkey = 23;\n'
    ret += 'unsigned char shellcode[{}] = {};'.format(
        str(len(shellcode)),
        '{' + '{}'.format(', '.join(str(x ^ xor_key) for x in shellcode)) + '}')
    return ret
