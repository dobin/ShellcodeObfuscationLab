#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
            return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
            return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
            return -1;              
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
            return -1;
    }
    
    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
            return -1;
    }
    
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
	
    return 0;
}

int main(void)
{
	{{ANTI_EMULATION}}

	{{SHELLCODE}}

	AESDecrypt((char *) shellcode, sizeof(shellcode), AESkey, sizeof(AESkey));

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
