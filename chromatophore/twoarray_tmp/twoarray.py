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


def split_list(input_list):
    even_list = []
    odd_list = []

    idx = 0
    for val in input_list:
        if (idx % 2) == 0:
            even_list.append(val)
        else:
            odd_list.append(val)
        idx = idx + 1

    return even_list, odd_list


def twoarray(input_file):
    shellcode = get_raw_sc(input_file)
    shellcode = list(shellcode)

    evenArray = []
    oddArray = []
    evenArray,oddArray = split_list(shellcode)

    ret = ""
    ret += '#define PAYLOAD_SIZE {0}\n'.format(str(len(shellcode)))
    ret += 'char evens[{0}] = {{{1}}};\n'.format(str(len(evenArray)),', '.join(hex(x) for x in evenArray))
    ret += 'char odds[{0}] = {{{1}}};\n'.format(str(len(oddArray)),', '.join(hex(x) for x in oddArray))
    return ret


