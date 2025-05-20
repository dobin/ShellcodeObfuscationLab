#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void)
{
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

        char shellcode[sizeof(reversed_payload)] = {0};
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
