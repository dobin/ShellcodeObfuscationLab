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


def reverse_byte_order(input_file):
    data = get_raw_sc(input_file)
    shellcode = list(data)

    hexbytes = ', '.join(hex(x) for x in shellcode[::-1])

    # Print in reverse order as hex bytes
    ret = 'char reversed_payload [{}] = {}'.format(
        len(shellcode),
        '{' + hexbytes + '};'
    )
    
    return ret
    
