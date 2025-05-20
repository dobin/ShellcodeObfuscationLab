import sys


def get_raw_sc(input_file):
    input_file = input_file
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
        return(file_shellcode)
    except FileNotFoundError:
        sys.exit("Supplied input file not found!")


def noobfuscation(input_file):
    shellcode = get_raw_sc(input_file)
    shellcode = list(shellcode)

    ret = ""
    ret += 'unsigned char shellcode[{}] = {};'.format(
        str(len(shellcode)),
        '{' + '{}'.format(', '.join(str(x) for x in shellcode)) + '}')
    return ret
