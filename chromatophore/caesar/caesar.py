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


def make_caesar(sc_list):
    sc = []
    for x in sc_list:
        if (int(x) + 13) > 255:
            sc.append(hex(x + 13 - 256))
        else:
            sc.append(hex(x + 13))
    return sc


def caesar(input_file):
    # read in our raw shellcode and get the length
    raw_sc = get_raw_sc(input_file)
    sc_list = list(raw_sc)

    new_sc = make_caesar(sc_list)
    ret = ""
    ret += 'char caesar[{0}] = {{{1}}};'.format(str(len(new_sc)), ', '.join(x for x in new_sc))
    ret += 'unsigned char shellcode[{}] = '.format(str(len(raw_sc))) + '{ 0x00 };'
    return ret
    