#include <windows.h>
#include <stdio.h>


int b64index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}


int base64_decode(const char* input, unsigned char* output) {
    int len = strlen(input);
    int out_idx = 0, val = 0, valb = -8;

    for (int i = 0; i < len; i++) {
        int idx = b64index(input[i]);
        if (idx == -1) continue;
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            output[out_idx++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }

    return out_idx;
}


int main() {
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

    BYTE* shellcode = (BYTE*)malloc(shellcodeLen);
    if (!shellcode) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    base64_decode(base64, shellcode);


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
