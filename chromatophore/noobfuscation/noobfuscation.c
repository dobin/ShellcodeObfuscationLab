#include <windows.h>
#include <stdio.h>


int main(void)
{
	{{ANTI_EMULATION}}
	{{SHELLCODE}}

	printf("All this program does is store shellcode and print this message.\n");

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

}
          
