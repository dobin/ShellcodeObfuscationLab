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


def reverse_hex_string(input_file):
    # read in our raw shellcode and get the length
    raw_sc = get_raw_sc(input_file)
    sc_len = len(raw_sc)

    shellcode = list(raw_sc)
    hex_string = '{}'.format(','.join(hex(x) for x in shellcode))

    # Print in reverse order as hex bytes
    ret = 'char reversed_hex_string[] = "{}";\n'.format(
        hex_string[::-1]
    )
    ret += "unsigned int shellcode_len = {};\n".format(
        str(sc_len)
    )
    
    return ret
