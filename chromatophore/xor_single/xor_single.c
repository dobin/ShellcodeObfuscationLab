#include <windows.h>
#include <stdio.h>


int main(void)
{	
	{{ANTI_EMULATION}}
	{{SHELLCODE}}

	// XOR each byte of our shellcode with the key to decode it
	for (int idx = 0;  idx < sizeof(shellcode); idx++) {
        shellcode[idx] = shellcode[idx] ^ xorkey;
	}

	int idx = 0;
	while ( idx < sizeof(shellcode))
	{
		if (idx == (sizeof(shellcode) - 1) )
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
          
