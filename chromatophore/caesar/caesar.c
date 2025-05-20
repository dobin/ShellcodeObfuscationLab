#include <windows.h>
#include <stdio.h>

int main(void)
{
	{{ANTI_EMULATION}}
	{{SHELLCODE}}

	for (int i = 0; i < sizeof(caesar); i++)
	{
		if ((caesar[i] - 13) < 0)
		{
			printf(""); // because defender
			shellcode[i] = caesar[i] + 256 - 13;
		}
		else
		{
			shellcode[i] = caesar[i] - 13;
		}
	}

	int idx = 0;
	while (idx < sizeof(shellcode))
	{
		if (idx == (sizeof(shellcode) - 1))
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
