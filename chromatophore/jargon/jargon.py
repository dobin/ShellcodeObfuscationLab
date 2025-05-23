import random
import sys


def gen_word_combinations(dict_file):
    # read in words dictionary
    try:
        with open(dict_file) as dictionary:
            words = dictionary.readlines()
    except FileNotFoundError:
        exit("\n\nThe dictionary you specified does not exist! Please specify a valid file path.\nExiting...\n")

    # Select random words from dictionary
    # why is this 257?  It fails at 256
    try:
        random_words = random.sample(words, 257)
        return random_words
    except ValueError:
        exit("\n\nThe dictionary file you specified does not contain at least 256 words!\nExiting...\n")


def get_shellcode(input_file):
    file_shellcode = b''
    try:
        with open(input_file, 'rb') as shellcode_file:
            file_shellcode = shellcode_file.read()
            file_shellcode = file_shellcode.strip()
            binary_code = ''

            for byte in file_shellcode:
                binary_code += "\\x" + hex(byte)[2:].zfill(2)

            raw_shellcode = "0" + ",0".join(binary_code.split("\\")[1:])

        return(raw_shellcode)
    
    except FileNotFoundError:
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")


def jargon(input_file):
    # absolute path because our working directory 
    # will be the root of the project
    dict_file = "chromatophore/jargon/google-10000-english-usa-5char.txt"

    '''
        Build translation table
    '''
    words = gen_word_combinations(dict_file)
    english_array = []
    for i in range(0, 256):
        english_array.append(words.pop(1).strip())

    tt_index = 0
    translation_table = 'unsigned char* translation_table[XXX] = { '
    for word in english_array:
        translation_table = translation_table + '"' + word + '",'
        tt_index = tt_index + 1

    translation_table = translation_table.rstrip(', ') + ' };\n'
    translation_table = translation_table.replace('XXX', str(tt_index))
    
    '''
        Read and format shellcode
    '''
    shellcode = get_shellcode(input_file)
    sc_len = len(shellcode.split(','))
    print('Shellcode length: ', sc_len)
    #sc_index = 0


    '''
        Translate shellcode using list comprehension
    '''
    translated_shellcode_gen = ('"{}"'.format(english_array[int(byte, 16)]) for byte in shellcode.split(','))
    translated_shellcode = 'unsigned char* translated_shellcode[XXX] = { ' + ','.join(translated_shellcode_gen)
    translated_shellcode = translated_shellcode.strip(',\'') + ' };\n'
    translated_shellcode = translated_shellcode.replace('XXX', str(sc_len))
    
    shellcode_var = "unsigned char shellcode[XXX] = {0};";
    shellcode_var = shellcode_var.replace('XXX', str(sc_len))

    generated_forloop = '''
        printf("Translating shellcode!\\n");
        /*
         for loop is defined as such:
          for (int sc_index = 0; sc_index < # of shelcode bytes; sc_index++)
        */
        for (int sc_index = 0; sc_index < XXX; sc_index++) {
                for (int tt_index = 0; tt_index <= 255; tt_index++) {
                        //if (translation_table[tt_index] == translated_shellcode[sc_index]) {
                        if (strcmp(translation_table[tt_index], translated_shellcode[sc_index]) == 0) {
                                shellcode[sc_index] = tt_index;
                                break;
                        }
                }
        }
'''
    generated_forloop = generated_forloop.replace('XXX', str(sc_len))
    
    '''
        Save the results
    '''
    res = ""
    res += translation_table + '\n'
    res += translated_shellcode + '\n'
    res += shellcode_var + '\n'
    res += 'int sc_len = sizeof(shellcode);\n'
    res += generated_forloop + '\n'
    return res
