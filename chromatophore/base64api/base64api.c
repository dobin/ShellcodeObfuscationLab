#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")


int main() {
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

    DWORD shellcodeLen = 0;

    // First, get required buffer size
    CryptStringToBinaryA(base64, 0, CRYPT_STRING_BASE64, NULL, &shellcodeLen, NULL, NULL);

    BYTE* shellcode = (BYTE*)malloc(shellcodeLen);
    if (!shellcode) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    if (CryptStringToBinaryA(base64, 0, CRYPT_STRING_BASE64, shellcode, &shellcodeLen, NULL, NULL)) {
        printf("shellcode (%lu bytes):\n", shellcodeLen);
        fwrite(shellcode, 1, shellcodeLen, stdout);
        printf("\n");
    } else {
        fprintf(stderr, "Decoding failed. Error code: %lu\n", GetLastError());
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
	

    free(shellcode);
    return 0;
}
