import sys
	
def repeated_key_xor(input_text, key):
    """Returns message XOR'd with a key. If the message is longer
    than the key, the key will repeat.
    """
    input_text = input_text
    key = key
    len_key = len(key)
    encoded = []

    for i in range(0, len(input_text)):
        encoded.append(input_text[i] ^ key[i % len_key])
    return bytes(encoded)


def format_shellcode(encrypted_shellcode):
    # Format shellcode
    encrypted_shellcode = encrypted_shellcode
    chunked_shellcode = ""
    chunked_shellcode = [encrypted_shellcode[i:i+2] for i in range(0, len(encrypted_shellcode), 2)]
    final_shellcode = ""
    for chunk in chunked_shellcode:
        final_shellcode += "0x" + str(chunk).zfill(2) + ","

    # trim trailing comma
    final_shellcode = final_shellcode.rstrip(',')

    return final_shellcode


def get_raw_sc(input_file):
    input_file = input_file
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
        return(file_shellcode)
    except FileNotFoundError:
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")

		
def DoBinary(raw_sc, key):
    key_bytes = bytes(key, 'UTF8')
    encrypted_shellcode = repeated_key_xor(raw_sc, key_bytes).hex()

    final_shellcode = format_shellcode(encrypted_shellcode)
    return final_shellcode


def xor_multibyte(input_file):
    xor_key = "XORKEY"
    raw_shellcode = get_raw_sc(input_file)
    shellcode = DoBinary(raw_shellcode, xor_key)

    ret = ""
    ret += 'char shellcode[{}] = {};\n'.format(
        str(len(raw_shellcode)),
        '{' + '{}'.format(shellcode) + '}') 
    ret += '\tchar xorkey[] = "{}";\n'.format(xor_key)

    return ret

